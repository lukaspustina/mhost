//! Definition of the `WaitAll` combinator, waiting for all of a list of futures
//! to finish and returns a `Result` for each.

use std;
use std::fmt;
use std::mem;

use futures::{self, Future, IntoFuture, Poll, Async};

#[derive(Debug)]
enum ElemState<T> where T: Future {
    Pending(T),
    Done(std::result::Result<T::Item, Box<std::error::Error>>),
}

#[must_use = "futures do nothing unless polled"]
pub struct WaitAll<I>
    where I: IntoIterator,
          I::Item: IntoFuture,
{
    elems: Vec<ElemState<<I::Item as IntoFuture>::Future>>,
}

impl<I> fmt::Debug for WaitAll<I>
    where I: IntoIterator,
          I::Item: IntoFuture,
          <<I as IntoIterator>::Item as IntoFuture>::Future: fmt::Debug,
          <<I as IntoIterator>::Item as IntoFuture>::Item: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("WaitAll")
            .field("elems", &self.elems)
            .finish()
    }
}

pub fn wait_all<I>(i: I) -> WaitAll<I>
    where I: IntoIterator,
          I::Item: IntoFuture,
{
    let elems = i.into_iter().map(|f| {
        ElemState::Pending(f.into_future())
    }).collect();
    WaitAll { elems: elems }
}

impl<I> Future for WaitAll<I>
    where I: IntoIterator,
          I::Item: IntoFuture,
          <<I as std::iter::IntoIterator>::Item as futures::IntoFuture>::Error: std::error::Error + 'static
{
    type Item = Vec<std::result::Result<<I::Item as IntoFuture>::Item, Box<std::error::Error>>>;
    // `WaitAll` return the individual errors for each Future. A global error does not make sense here
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let mut all_done = true;

        for idx in 0 .. self.elems.len() {
            let done_val = match self.elems[idx] {
                ElemState::Pending(ref mut t) => {
                    match t.poll() {
                        Ok(Async::Ready(v)) => Ok(v),
                        Ok(Async::NotReady) => {
                            all_done = false;
                            continue
                        }
                        Err(e) => Err(e),
                    }
                }
                ElemState::Done(ref mut _v) => continue,
            };

            match done_val {
                Ok(v) => self.elems[idx] = ElemState::Done(Ok(v)),
                Err(e) => self.elems[idx] = ElemState::Done(Err(Box::new(e))),
            }
        }

        if all_done {
            let elems = mem::replace(&mut self.elems, Vec::new());
            let result = elems.into_iter().map(|e| {
                match e {
                    ElemState::Done(t) => t,
                    _ => unreachable!(),
                }
            }).collect();
            Ok(Async::Ready(result))
        } else {
            Ok(Async::NotReady)
        }
    }
}
