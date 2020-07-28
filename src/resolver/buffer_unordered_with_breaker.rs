use core::pin::Pin;
use futures::stream::{Fuse, FuturesUnordered, StreamExt};
use futures::task::{Context, Poll};
use futures::{Future, Stream};
#[cfg(feature = "sink")]
use futures_sink::Sink;
use pin_project::{pin_project, project};

/*
pub trait StreamExtBufferUnorderedWithBreaker<St>
    where
    St: Stream,
    St::Item: Future {
    fn buffered_unordered_with_breaker<St>(stream: St, n: usize, breaker: Box<dyn Fn(&<St::Item as Future>::Output) -> bool>)
                                           -> BufferUnorderedWithBreaker<St>;
}

impl<St: ?Sized> StreamExtBufferUnorderedWithBreaker for St where St: Stream, St::Item: Future
{
    fn buffered_unordered_with_breaker(stream: St, n: usize, breaker: Box<dyn Fn(&<St::Item as Future>::Output) -> bool>)
                                           -> BufferUnorderedWithBreaker<St> {
        BufferUBufferUnorderedWithBreakernordered::new(stream, n, breaker)
    }
}
 */

#[pin_project]
#[must_use = "streams do nothing unless polled"]
pub struct BufferUnorderedWithBreaker<St>
where
    St: Stream,
    St::Item: Future,
{
    #[pin]
    stream: Fuse<St>,
    in_progress_queue: FuturesUnordered<St::Item>,
    max: usize,
    breaker: Box<dyn Fn(&<St::Item as Future>::Output) -> bool>,
    abort: bool,
}

impl<St> BufferUnorderedWithBreaker<St>
where
    St: Stream,
    St::Item: Future,
{
    pub(crate) fn new(
        stream: St,
        n: usize,
        breaker: Box<dyn Fn(&<St::Item as Future>::Output) -> bool>,
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

impl<St> Stream for BufferUnorderedWithBreaker<St>
where
    St: Stream,
    St::Item: Future,
{
    type Item = <St::Item as Future>::Output;

    #[project]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        #[project]
        let BufferUnorderedWithBreaker {
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
