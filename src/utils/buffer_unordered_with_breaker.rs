// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Code stolen from futures crate -- <https://docs.rs/futures-util/0.3.5/src/futures_util/stream/stream/buffer_unordered.rs.html#15-23>
use core::pin::Pin;

use futures::stream::{Fuse, FuturesUnordered, StreamExt};
use futures::task::{Context, Poll};
use futures::{Future, Stream};
use pin_project::pin_project;

impl<T: ?Sized> StreamExtBufferUnorderedWithBreaker for T where T: StreamExt {}

#[allow(clippy::type_complexity)]
pub trait StreamExtBufferUnorderedWithBreaker: StreamExt {
    fn buffered_unordered_with_breaker(
        self,
        n: usize,
        breaker: Box<dyn Fn(&<Self::Item as Future>::Output) -> bool + Send>,
    ) -> BufferUnorderedWithBreaker<Self>
    where
        Self: Sized,
        Self::Item: Future,
    {
        BufferUnorderedWithBreaker::new(self, n, breaker)
    }
}

#[pin_project(project = BufferUnorderedWithBreakerProj)]
#[must_use = "streams do nothing unless polled"]
#[allow(clippy::type_complexity)]
pub struct BufferUnorderedWithBreaker<St>
where
    St: Stream,
    St::Item: Future,
{
    #[pin]
    stream: Fuse<St>,
    in_progress_queue: FuturesUnordered<St::Item>,
    max: usize,
    breaker: Box<dyn Fn(&<St::Item as Future>::Output) -> bool + Send>,
    abort: bool,
}

impl<St> BufferUnorderedWithBreaker<St>
where
    St: Stream,
    St::Item: Future,
{
    #[allow(clippy::type_complexity)]
    pub(crate) fn new(
        stream: St,
        n: usize,
        breaker: Box<dyn Fn(&<St::Item as Future>::Output) -> bool + Send>,
    ) -> BufferUnorderedWithBreaker<St>
    where
        St: Stream,
        St::Item: Future,
    {
        BufferUnorderedWithBreaker {
            stream: stream.fuse(),
            in_progress_queue: FuturesUnordered::new(),
            max: n,
            breaker,
            abort: false,
        }
    }
}

/// Stops polling all other futures on next poll after the breaker returns true.
/// The item that triggered the break is still yielded, then the stream terminates.
impl<St> Stream for BufferUnorderedWithBreaker<St>
where
    St: Stream,
    St::Item: Future,
{
    type Item = <St::Item as Future>::Output;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let BufferUnorderedWithBreakerProj {
            mut stream,
            in_progress_queue,
            max,
            breaker,
            abort,
        } = self.project();

        if *abort {
            return Poll::Ready(None);
        }

        // First up, try to spawn off as many futures as possible by filling up
        // our queue of futures.
        while in_progress_queue.len() < *max {
            match stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(fut)) => in_progress_queue.push(fut),
                Poll::Ready(None) | Poll::Pending => break,
            }
        }

        // Attempt to pull the next value from the in_progress_queue
        match in_progress_queue.poll_next_unpin(cx) {
            x @ Poll::Pending => return x,
            Poll::Ready(Some(item)) if breaker(&item) => {
                *abort = true;
                return Poll::Ready(Some(item));
            }
            x @ Poll::Ready(Some(_)) => return x,
            Poll::Ready(None) => {}
        }

        // If more values are still coming from the stream, we're not done yet
        if stream.is_done() {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;

    fn ok_future(v: i32) -> futures::future::Ready<Result<i32, &'static str>> {
        futures::future::ready(Ok(v))
    }

    fn err_future(e: &'static str) -> futures::future::Ready<Result<i32, &'static str>> {
        futures::future::ready(Err(e))
    }

    #[tokio::test]
    async fn all_futures_complete_without_breaker() {
        let items: Vec<_> = stream::iter(vec![ok_future(1), ok_future(2), ok_future(3)])
            .buffered_unordered_with_breaker(10, Box::new(|_| false))
            .collect()
            .await;

        assert_eq!(items.len(), 3);
        let mut values: Vec<i32> = items.into_iter().map(|r: Result<i32, &str>| r.unwrap()).collect();
        values.sort();
        assert_eq!(values, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn breaker_stops_stream_on_error() {
        let items: Vec<_> = stream::iter(vec![
            ok_future(1),
            err_future("fail"),
            ok_future(3),
            ok_future(4),
            ok_future(5),
        ])
        .buffered_unordered_with_breaker(1, Box::new(|r: &Result<i32, &str>| r.is_err()))
        .collect()
        .await;

        // With concurrency=1, we get items in order: Ok(1), then Err("fail") triggers break.
        // The breaker item is still yielded, then stream terminates.
        assert!(
            items.len() <= 3,
            "breaker should stop the stream early, got {} items",
            items.len()
        );
        assert!(
            items.iter().any(|r: &Result<i32, &str>| r.is_err()),
            "should contain the error that triggered the break"
        );
    }

    #[tokio::test]
    async fn empty_stream() {
        let items: Vec<Result<i32, &str>> = stream::iter(Vec::<futures::future::Ready<Result<i32, &str>>>::new())
            .buffered_unordered_with_breaker(10, Box::new(|_| false))
            .collect()
            .await;

        assert!(items.is_empty());
    }

    #[tokio::test]
    async fn single_future() {
        let items: Vec<_> = stream::iter(vec![futures::future::ready(42)])
            .buffered_unordered_with_breaker(10, Box::new(|_| false))
            .collect()
            .await;

        assert_eq!(items, vec![42]);
    }

    #[tokio::test]
    async fn concurrency_limit_respected() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let max_concurrent = Arc::new(AtomicUsize::new(0));
        let current = Arc::new(AtomicUsize::new(0));

        let futures: Vec<_> = (0..10)
            .map(|i| {
                let current = current.clone();
                let max_concurrent = max_concurrent.clone();
                async move {
                    let c = current.fetch_add(1, Ordering::SeqCst) + 1;
                    max_concurrent.fetch_max(c, Ordering::SeqCst);
                    tokio::task::yield_now().await;
                    current.fetch_sub(1, Ordering::SeqCst);
                    i
                }
            })
            .collect();

        let items: Vec<_> = stream::iter(futures)
            .buffered_unordered_with_breaker(3, Box::new(|_| false))
            .collect()
            .await;

        assert_eq!(items.len(), 10);
        assert!(
            max_concurrent.load(Ordering::SeqCst) <= 3,
            "max concurrent {} exceeded limit of 3",
            max_concurrent.load(Ordering::SeqCst)
        );
    }
}
