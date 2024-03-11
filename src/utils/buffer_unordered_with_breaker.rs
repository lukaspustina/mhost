// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Code stolen from futures crate -- https://docs.rs/futures-util/0.3.5/src/futures_util/stream/stream/buffer_unordered.rs.html#15-23
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

/// Stops polling all other futures on next poll after first Err is returned. In this way,
/// we get to see the Err which cased the break.
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
