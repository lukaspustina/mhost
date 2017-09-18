extern crate futures;
extern crate tokio_core;
extern crate trust_dns;

use futures::Future;
use std::cmp::Ordering;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use tokio_core::reactor::Core;
use trust_dns::client::{ClientFuture, BasicClientHandle, ClientHandle};
use trust_dns::rr::domain;
use trust_dns::rr::{DNSClass, RData, RecordType};
use trust_dns::udp::UdpClientStream;

fn main() {

    let mut io_loop = Core::new().unwrap();
    let addr: SocketAddr = ("8.8.8.8", 53).to_socket_addrs().unwrap().next().unwrap();
    let (stream, sender) = UdpClientStream::new(addr, &io_loop.handle());
    let mut client = ClientFuture::new(stream, sender, &io_loop.handle(), None);

    // TODO: timeouts on these requests so that the test doesn't hang
    io_loop.run(test_query(&mut client)).unwrap();
}

fn test_query(client: &mut BasicClientHandle) -> Box<Future<Item = (), Error = ()>> {
    let name = domain::Name::from_labels(vec!["WWW", "example", "com"]);

    Box::new(
        client
            .query(name.clone(), DNSClass::IN, RecordType::A)
            .map(move |response| {
                println!("response records: {:?}", response);
                assert_eq!(
                    response
                        .queries()
                        .first()
                        .expect("expected query")
                        .name()
                        .cmp_with_case(&name, false),
                    Ordering::Equal
                );

                let record = &response.answers()[0];
                assert_eq!(record.name(), &name);
                assert_eq!(record.rr_type(), RecordType::A);
                assert_eq!(record.dns_class(), DNSClass::IN);

                if let &RData::A(ref address) = record.rdata() {
                    assert_eq!(address, &Ipv4Addr::new(93, 184, 216, 34))
                } else {
                    assert!(false);
                }
            })
            .map_err(|e| {
                assert!(false, "query failed: {}", e);
            }),
    )
}
