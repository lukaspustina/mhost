// TODO: deny missing docs
#![allow(missing_docs)]

extern crate futures;
extern crate tokio_core;
extern crate trust_dns;

use futures::Future;
use futures::future::join_all;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use tokio_core::reactor::Handle;
use trust_dns::client::{ClientFuture, ClientHandle};
use trust_dns::rr::domain;
use trust_dns::rr::{DNSClass, RData, RecordType};
use trust_dns::udp::UdpClientStream;

pub fn lookup<T: Into<SocketAddr>>(
    loop_handle: &Handle,
    domain_name: &str,
    server: T,
) -> Box<Future<Item = Option<Ipv4Addr>, Error = ()>> {
    let socket_address = server.into();
    let (stream, sender) = UdpClientStream::new(socket_address, loop_handle);
    let mut client = ClientFuture::new(stream, sender, loop_handle, None);
    let domain_name = domain::Name::from_str(domain_name).unwrap();

    Box::new(
        client
            .query(domain_name, DNSClass::IN, RecordType::A)
            .map(move |response| {
                let record = &response.answers()[0];
                if let RData::A(address) = *record.rdata() {
                    Some(address)
                } else {
                    None
                }
            })
            .map_err(move |_| ()),
    )
}

pub fn multiple_lookup<T: Into<SocketAddr>>(
    loop_handle: &Handle,
    domain_name: &str,
    servers: Vec<T>,
) -> Box<Future<Item = Vec<Option<Ipv4Addr>>, Error = ()>> {
    let futures: Vec<_> = servers
        .into_iter()
        .map(|server| lookup(loop_handle, domain_name, server))
        .collect();

    Box::new(join_all(futures))
}

#[cfg(test)]
mod test {
    use super::*;
    use tokio_core::reactor::Core;

    #[test]
    fn lookup_with_google() {
        let mut io_loop = Core::new().unwrap();
        let host = "example.com";
        let server = (Ipv4Addr::from_str("8.8.8.8").unwrap(), 53);

        let lookup = lookup(&io_loop.handle(), host, server);
        let results = io_loop.run(lookup);

        assert_eq!(results.unwrap(), Some(Ipv4Addr::new(93, 184, 216, 34)));
    }

    #[test]
    fn multiple_lookup_with_google() {
        let mut io_loop = Core::new().unwrap();
        let host = "example.com";
        let servers = vec![
            (Ipv4Addr::from_str("8.8.8.8").unwrap(), 53),
            (Ipv4Addr::from_str("8.8.4.4").unwrap(), 53),
        ];

        let lookup = multiple_lookup(&io_loop.handle(), host, servers);
        let results = io_loop.run(lookup);

        assert!(results.is_ok());
        let addresses = results.unwrap();
        assert_eq!(addresses[0], Some(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(addresses[1], Some(Ipv4Addr::new(93, 184, 216, 34)));
    }
}
