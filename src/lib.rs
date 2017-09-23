// TODO: deny missing docs
#![allow(missing_docs)]
// for mem::discriminant_value
#![feature(discriminant_value)]

#[macro_use]
extern crate error_chain;
extern crate futures;
extern crate tokio_core;
extern crate trust_dns;

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use tokio_core::reactor::Handle;
use trust_dns::client::{ClientFuture, ClientHandle};
use trust_dns::rr::domain;
use trust_dns::rr::{DNSClass, Record, RecordType};
use trust_dns::udp::UdpClientStream;

#[derive(Debug)]
pub struct DnsResponse {
    pub server: IpAddr,
    pub answers: Vec<Record>,
}

/// Definition of the `WaitAll` combinator, waiting for all of a list of futures
/// to finish.

use std::prelude::v1::*;

use std::fmt;
use std::mem;

use futures::{Future, IntoFuture, Poll, Async};

#[derive(Debug)]
enum ElemState<T> where T: Future {
    Pending(T),
    Done(T::Item),
    Failed,
}

/// A future which takes a list of futures and resolves with a vector of the
/// completed values.
///
/// This future is created with the `wait_all` method.
#[must_use = "futures do nothing unless polled"]
pub struct WaitAll<I>
    where I: IntoIterator,
          I::Item: IntoFuture,
{
    elems: Vec<ElemState<<I::Item as IntoFuture>::Future>>,
    errors: Vec<<I::Item as IntoFuture>::Error>,
}

impl<I> fmt::Debug for WaitAll<I>
    where I: IntoIterator,
          I::Item: IntoFuture,
          <<I as IntoIterator>::Item as IntoFuture>::Future: fmt::Debug,
          <<I as IntoIterator>::Item as IntoFuture>::Item: fmt::Debug,
          <<I as IntoIterator>::Item as IntoFuture>::Error: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("WaitAll")
            .field("elems", &self.elems)
            .field("errors", &self.errors)
            .finish()
    }
}

/// Creates a future which represents a collection of the results of the futures
/// given.
///
/// The returned future will drive execution for all of its underlying futures,
/// collecting the results into a destination `Vec<T>` in the same order as they
/// were provided. If any future returns an error then all other futures will be
/// canceled and an error will be returned immediately. If all futures complete
/// successfully, however, then the returned future will succeed with a `Vec` of
/// all the successful results.
///
/// # Examples
///
/// ```
/// use mhost::*;
/// use futures::future::*;
///
/// let f = wait_all(vec![
///     ok::<u32, u32>(1),
///     ok::<u32, u32>(2),
///     ok::<u32, u32>(3),
/// ]);
/// let f = f.map(|x| {
///     assert_eq!(x, [1, 2, 3]);
/// });
///
/// let f = wait_all(vec![
///     ok::<u32, u32>(1).boxed(),
///     err::<u32, u32>(2).boxed(),
///     ok::<u32, u32>(3).boxed(),
/// ]);
/// let f = f.then(|x| {
///     assert_eq!(x, Err(2));
///     x
/// });
/// ```
pub fn wait_all<I>(i: I) -> WaitAll<I>
    where I: IntoIterator,
          I::Item: IntoFuture,
{
    let elems = i.into_iter().map(|f| {
        ElemState::Pending(f.into_future())
    }).collect();
    WaitAll { elems: elems, errors: Vec::new() }
}

impl<I> Future for WaitAll<I>
    where I: IntoIterator,
          I::Item: IntoFuture,
{
    type Item = Vec<<I::Item as IntoFuture>::Item>;
    type Error = Vec<<I::Item as IntoFuture>::Error>;


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
                ElemState::Failed => continue,
            };

            match done_val {
                Ok(v) => self.elems[idx] = ElemState::Done(v),
                Err(err) => {
                    self.elems[idx] = ElemState::Failed;
                    self.errors.push(err);
                }
            }
        }

        if all_done {
            let elems = mem::replace(&mut self.elems, Vec::new());
            let result = elems
                .into_iter()
                .filter(|e| {
                    match *e {
                        ElemState::Failed => false,
                        _ => true,
                    }
                })
                .map(|e| {
                    match e {
                        ElemState::Done(t) => t,
                        _ => unreachable!(),
                    }
                })
                .collect();
            Ok(Async::Ready(result))
        } else {
            Ok(Async::NotReady)
        }
    }
}

pub fn lookup<T: Into<SocketAddr>>(
    loop_handle: &Handle,
    domain_name: &str,
    server: T,
    record_type: RecordType
) -> Box<Future<Item=DnsResponse, Error=Error>> {
    let socket_address = server.into();
    let (stream, sender) = UdpClientStream::new(socket_address, loop_handle);
    let mut client = ClientFuture::new(stream, sender, loop_handle, None);
    let domain_name = domain::Name::from_str(domain_name).unwrap();

    Box::new(
        client
            .query(domain_name, DNSClass::IN, record_type)
            .map(move |mut response| {
                DnsResponse { server: socket_address.ip(), answers: response.take_answers() }
            })
            .map_err(move |e| {
                Error::with_chain(e, ErrorKind::QueryError)
            })
    )
}

pub fn multiple_lookup<T: Into<SocketAddr>>(
    loop_handle: &Handle,
    domain_name: &str,
    servers: Vec<T>,
    record_type: RecordType ,
) -> Box<Future<Item=Vec<DnsResponse>, Error=Vec<Error>>> {
    let futures: Vec<_> = servers
        .into_iter()
        .map(|server| lookup(loop_handle, domain_name, server, record_type))
        .collect();

    Box::new(wait_all(futures))
}

error_chain! {
    types {
        Error, ErrorKind, ResultExt, Result;
    }

    errors {
        QueryError {
            description("Query failed")
            display("Query failed")
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::mem;
    use std::net::Ipv4Addr;
    use tokio_core::reactor::Core;
    use trust_dns::rr::{RData, RecordType};

    #[test]
    fn lookup_with_google() {
        let mut io_loop = Core::new().unwrap();
        let host = "example.com";
        let server = (Ipv4Addr::from_str("8.8.8.8").unwrap(), 53);

        let lookup = lookup(&io_loop.handle(), host, server, RecordType::A);
        let result = io_loop.run(lookup).unwrap();
        let response: DnsResponse = result;

        assert_eq!(response.server, Ipv4Addr::from_str("8.8.8.8").unwrap());
        assert_eq!(response.answers.len(), 1);
        assert!(is_A_record(response.answers[0].rdata()));
        if let RData::A(ip) = *response.answers[0].rdata() {
            assert_eq!(ip, Ipv4Addr::new(93, 184, 216, 34));
        }
    }

    #[test]
    fn multiple_lookup_with_google() {
        let mut io_loop = Core::new().unwrap();
        let host = "example.com";
        let servers = vec![
            (Ipv4Addr::from_str("8.8.8.8").unwrap(), 53),
            (Ipv4Addr::from_str("8.8.4.4").unwrap(), 53),
        ];

        let lookup = multiple_lookup(&io_loop.handle(), host, servers, RecordType::A);
        let mut responses: Vec<_> = io_loop.run(lookup).unwrap();
        assert_eq!(responses.len(), 2);

        let response = responses.pop().unwrap();
        assert_eq!(response.server, Ipv4Addr::from_str("8.8.4.4").unwrap());
        assert_eq!(response.answers.len(), 1);
        assert!(is_A_record(response.answers[0].rdata()));
        if let RData::A(ip) = *response.answers[0].rdata() {
            assert_eq!(ip, Ipv4Addr::new(93, 184, 216, 34));
        }

        let response = responses.pop().unwrap();
        assert_eq!(response.server, Ipv4Addr::from_str("8.8.8.8").unwrap());
        assert_eq!(response.answers.len(), 1);
        assert!(is_A_record(response.answers[0].rdata()));
        if let RData::A(ip) = *response.answers[0].rdata() {
            assert_eq!(ip, Ipv4Addr::new(93, 184, 216, 34));
        }
    }

    #[allow(non_snake_case)]
    fn is_A_record(rdata: &RData) -> bool {
        mem::discriminant(rdata) == mem::discriminant(&RData::A(Ipv4Addr::new(127, 0, 0, 1)))
    }
}
