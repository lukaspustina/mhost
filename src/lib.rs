// TODO: deny missing docs
#![allow(missing_docs)]
// for mem::discriminant_value
#![feature(discriminant_value)]

#[macro_use]
extern crate error_chain;
extern crate futures;
extern crate tokio_core;
extern crate trust_dns;

mod future;

use futures::Future;
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
    record_type: RecordType,
) -> Box<Future<Item=Vec<std::result::Result<DnsResponse, Box<std::error::Error>>>, Error=()>> {
    let futures: Vec<_> = servers
        .into_iter()
        .map(|server| lookup(loop_handle, domain_name, server, record_type))
        .collect();

    Box::new(future::wait_all(futures))
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
    fn multiple_lookup_with_google_ok() {
        let mut io_loop = Core::new().unwrap();
        let host = "example.com";
        let servers = vec![
            (Ipv4Addr::from_str("8.8.8.8").unwrap(), 53),
            (Ipv4Addr::from_str("8.8.4.4").unwrap(), 53),
        ];

        let lookup = multiple_lookup(&io_loop.handle(), host, servers, RecordType::A);
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

    #[test]
    fn multiple_lookup_with_google_fail1() {
        let mut io_loop = Core::new().unwrap();
        let host = "example.com";
        let servers = vec![
            (Ipv4Addr::from_str("8.8.8.8").unwrap(), 53),
            (Ipv4Addr::from_str("8.8.5.5").unwrap(), 53),
        ];

        let lookup = multiple_lookup(&io_loop.handle(), host, servers, RecordType::A);
        let mut responses: Vec<_> = io_loop.run(lookup).unwrap();
        assert_eq!(responses.len(), 2);

        let response = responses.pop().unwrap();
        assert!(response.is_err());

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
