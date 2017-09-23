// TODO: deny missing docs
#![allow(missing_docs)]
// for mem::discriminant_value
#![feature(discriminant_value)]

#[macro_use]
extern crate error_chain;
extern crate futures;
extern crate tokio_core;
extern crate trust_dns;

use futures::Future;
use futures::future::join_all;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;
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

/// Lookup a domain name against a single DNS server
///
/// The return type is special here. `Future<Item=Result<DnsResponse>, Error=()`. This Future is not supposed to fail
/// in future::futures::Err way, but rather propagate errors as part of the Future's successful execution.
/// In this way, `multiple_lookup` does not abort when lookups fail, but wait for all queries / Futures to finish.
/// The library user than can distinguish between successful and failed lookups.
///
/// See also `multiple_lookup`.
pub fn lookup<T: Into<SocketAddr>>(
    loop_handle: &Handle,
    domain_name: &str,
    server: T,
    record_type: RecordType,
    timeout: Duration
) -> Box<Future<Item=Result<DnsResponse>, Error=()>> {
    let socket_address = server.into();
    let (stream, sender) = UdpClientStream::new(socket_address, loop_handle);
    let mut client = ClientFuture::with_timeout(stream, sender, loop_handle, timeout, None);
    let domain_name = domain::Name::from_str(domain_name).unwrap();

    Box::new(
        client
            .query(domain_name, DNSClass::IN, record_type)
            .map(move |mut response| {
                Ok(DnsResponse { server: socket_address.ip(), answers: response.take_answers() })
            })
            .or_else(move |e| {
                Ok(Err(Error::with_chain(e, ErrorKind::QueryError)))
            })
    )
}

pub fn multiple_lookup<T: Into<SocketAddr>>(
    loop_handle: &Handle,
    domain_name: &str,
    servers: Vec<T>,
    record_type: RecordType,
    timeout: Duration
) -> Box<Future<Item=Vec<Result<DnsResponse>>, Error=()>> {
    let futures: Vec<_> = servers
        .into_iter()
        .map(|server| lookup(loop_handle, domain_name, server, record_type, timeout))
        .collect();

    Box::new(join_all(futures))
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

        let lookup = lookup(&io_loop.handle(), host, server, RecordType::A, Duration::from_secs(5));
        let result = io_loop.run(lookup).unwrap();
        let response: DnsResponse = result.unwrap();

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

        let lookup = multiple_lookup(&io_loop.handle(), host, servers, RecordType::A, Duration::from_secs(5));
        let mut responses: Vec<_> = io_loop.run(lookup).unwrap();
        assert_eq!(responses.len(), 2);

        let response = responses.pop().unwrap().unwrap();
        assert_eq!(response.server, Ipv4Addr::from_str("8.8.4.4").unwrap());
        assert_eq!(response.answers.len(), 1);
        assert!(is_A_record(response.answers[0].rdata()));
        if let RData::A(ip) = *response.answers[0].rdata() {
            assert_eq!(ip, Ipv4Addr::new(93, 184, 216, 34));
        }

        let response = responses.pop().unwrap().unwrap();
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
