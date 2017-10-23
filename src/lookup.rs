// TODO: deny missing docs
#![allow(missing_docs)]

use futures::{self, Future, Stream};
use futures::future::join_all;
use futures::stream::futures_unordered;
use log::{LogLevel, max_log_level};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use std::str::FromStr;
use tokio_core::reactor::Handle;
use trust_dns::client::{ClientFuture, ClientHandle};
use trust_dns::rr::domain;
use trust_dns::rr::{DNSClass, Record, RecordType};
use trust_dns::udp::UdpClientStream;

#[derive(Debug, Clone)]
pub struct Query {
    domain_name: domain::Name,
    record_types: Vec<RecordType>,
    timeout: Duration,
}

impl Query {
    pub fn from<T: Into<domain::Name>>(domain_name: T, record_types: Vec<RecordType>) -> Query {
        Query {
            domain_name: domain_name.into(),
            record_types,
            timeout: Duration::from_secs(5),
        }
    }

    pub fn new(domain_name: &str, record_types: Vec<RecordType>) -> Query {
        let domain_name = domain::Name::from_str(domain_name).unwrap();
        Query::from(domain_name, record_types)
    }

    pub fn set_timeout(mut self: Self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn add_recordtype(mut self: Self, record_type: RecordType) -> Self {
        self.record_types.push(record_type);
        self
    }
}

#[derive(Debug)]
pub struct Response {
    pub server: IpAddr,
    pub answers: Vec<Record>,
}

pub fn lookup<T: Into<SocketAddr>>(
    loop_handle: &Handle,
    query: Query,
    server: T,
) -> Box<Future<Item=Response, Error=Error>> {
    let socket_addr = server.into();
    let domain_name = query.domain_name;

    let (stream, sender) = UdpClientStream::new(socket_addr, loop_handle);
    let mut client = ClientFuture::with_timeout(stream, sender, loop_handle, query.timeout, None);

    let lookups: Vec<_> = query
        .record_types
        .into_iter()
        .enumerate()
        .map(|(index, rt)| {
            client
                .query(domain_name.clone(), DNSClass::IN, rt)
                .map(move |mut response| {
                    trace!("{} successfully responded to {}. query for {} with {} answers.",
                           socket_addr.ip(), index+1, rt, response.answers().len());
                    Response {
                        server: socket_addr.ip(),
                        answers: response.take_answers(),
                    }
                })
                .map_err(move |e| {
                    info!("{} failed {}. query for {} because {}.", socket_addr.ip(), index+1, rt, e);
                    Error::with_chain(e, ErrorKind::QueryError(index + 1, rt, socket_addr.ip()))
                })
        })
        .collect();
    let all = join_all(lookups).and_then(move |lookups| {
        let all_answers = lookups.into_iter().fold(Vec::new(), |mut acc,
                                                                mut lookup: Response| {
            acc.append(&mut lookup.answers);
            acc
        });

        // Don't double log servers with 0 answers in Debug
        if max_log_level() == LogLevel::Info && all_answers.is_empty() {
            info!("{} responded with 0 answers.", socket_addr.ip());
        } else {
            debug!("{} responded with {} answers.", socket_addr.ip(), all_answers.len());
        }

        futures::future::ok(Response {
            server: socket_addr.ip(),
            answers: all_answers,
        })
    });

    Box::new(all)
}

/// Lookup a domain name against a set of DNS servers
///
/// The return type is special here. `Future<Item=Vec<Result<DnsResponse>>, Error=()`. This Future is not supposed to fail
/// in `future::futures::Err` way, but rather propagate errors as part of the Future's successful execution.
/// In this way, this function does not abort when single lookups fail, but wait for all queries / Futures to finish.
/// The library user than can distinguish between successful and failed lookups.
#[allow(needless_pass_by_value)]
pub fn multiple_lookup<T: Into<SocketAddr>>(
    loop_handle: &Handle,
    query: Query,
    servers: Vec<T>,
) -> Box<Future<Item=Vec<Result<Response>>, Error=()>> {
    let futures: Vec<_> = servers
        .into_iter()
        .map(|server| {
            lookup(loop_handle, query.clone(), server).map(Ok).or_else(
                |e| {
                    Ok(Err(e))
                },
            )
        })
        .collect();

    Box::new(futures_unordered(futures).collect())
}

error_chain! {
    types {
        Error, ErrorKind, ResultExt, Result;
    }

    errors {
        QueryError(index: usize, rt: RecordType, ip: IpAddr) {
            description("Query failed")
            display("{}. query for {:?} record against DNS server {} failed", index, rt, ip)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
    use tokio_core::reactor::Core;
    use trust_dns::rr::{RData, RecordType};


    #[test]
    fn lookup_with_google() {
        let mut io_loop = Core::new().unwrap();
        let domain_name = "example.com";
        let query = Query::new(domain_name, vec![RecordType::A]);
        let server = (Ipv4Addr::from_str("8.8.8.8").unwrap(), 53);

        let lookup = lookup(&io_loop.handle(), query, server);
        let result = io_loop.run(lookup).unwrap();
        let response: Response = result;

        assert_eq!(response.server, Ipv4Addr::from_str("8.8.8.8").unwrap());
        assert_eq!(response.answers.len(), 1);
        if let RData::A(ip) = *response.answers[0].rdata() {
            assert_eq!(ip, Ipv4Addr::new(93, 184, 216, 34));
        } else {
            panic!("Not a PTR record");
        }
    }

    #[test]
    fn ptr_lookup_with_google() {
        let mut io_loop = Core::new().unwrap();
        let ip_addr = IpAddr::from_str("8.8.8.8").unwrap();
        let query = Query::from(ip_addr, vec![RecordType::PTR]);
        let server = (Ipv4Addr::from_str("8.8.8.8").unwrap(), 53);

        let lookup = lookup(&io_loop.handle(), query, server);
        let result = io_loop.run(lookup).unwrap();
        let response: Response = result;

        assert_eq!(response.server, Ipv4Addr::from_str("8.8.8.8").unwrap());
        assert_eq!(response.answers.len(), 1);
        if let RData::PTR(ref ptr) = *response.answers[0].rdata() {
            assert_eq!(
                ptr,
                &domain::Name::from_str("google-public-dns-a.google.com.").unwrap()
            );
        } else {
            panic!("Not a PTR record");
        }
    }

    #[test]
    fn multiple_lookup_with_google_ok() {
        let mut io_loop = Core::new().unwrap();
        let domain_name = "example.com";
        let query = Query::new(domain_name, vec![RecordType::A]);
        let servers = vec![
            (Ipv4Addr::from_str("8.8.4.4").unwrap(), 53),
            (Ipv4Addr::from_str("8.8.8.8").unwrap(), 53),
        ];

        let lookup = multiple_lookup(&io_loop.handle(), query, servers);
        let results: ::std::result::Result<Vec<_>, _> = io_loop.run(lookup)
            .unwrap()
            .into_iter()
            .collect();
        let mut responses = results.unwrap();

        assert_eq!(responses.len(), 2);
        responses.sort_by(|a, b| a.server.cmp(&b.server));

        let response = responses.pop().unwrap();
        assert_eq!(response.server, Ipv4Addr::from_str("8.8.8.8").unwrap());
        assert_eq!(response.answers.len(), 1);
        if let RData::A(ip) = *response.answers[0].rdata() {
            assert_eq!(ip, Ipv4Addr::new(93, 184, 216, 34));
        } else {
            panic!("Not an A record");
        }

        let response = responses.pop().unwrap();
        assert_eq!(response.server, Ipv4Addr::from_str("8.8.4.4").unwrap());
        assert_eq!(response.answers.len(), 1);
        if let RData::A(ip) = *response.answers[0].rdata() {
            assert_eq!(ip, Ipv4Addr::new(93, 184, 216, 34));
        } else {
            panic!("Not an A record");
        }
    }

    #[test]
    fn multiple_lookup_with_google_fail_1() {
        let mut io_loop = Core::new().unwrap();
        let domain_name = "example.com";
        // short timeout, because we won't the test to take too long, Google is fast enough to answer in time
        let query =
            Query::new(domain_name, vec![RecordType::A]).set_timeout(Duration::from_millis(500));
        let servers = vec![
            (Ipv4Addr::from_str("8.8.8.8").unwrap(), 53),
            // This one does not exists and should lead to a timeout
            (Ipv4Addr::from_str("8.8.5.5").unwrap(), 53),
        ];

        let lookup = multiple_lookup(&io_loop.handle(), query, servers);
        let mut responses: Vec<_> = io_loop.run(lookup).unwrap();
        assert_eq!(responses.len(), 2);

        let response = responses.pop().unwrap();
        assert!(response.is_err());

        let response = responses.pop().unwrap().unwrap();
        assert_eq!(response.server, Ipv4Addr::from_str("8.8.8.8").unwrap());
        assert_eq!(response.answers.len(), 1);
        if let RData::A(ip) = *response.answers[0].rdata() {
            assert_eq!(ip, Ipv4Addr::new(93, 184, 216, 34));
        } else {
            panic!("Not an A record");
        }
    }

    #[test]
    fn multi_record_type_lookup() {
        let mut io_loop = Core::new().unwrap();
        let server = (Ipv4Addr::from_str("8.8.8.8").unwrap(), 53);

        let record_types = vec![RecordType::A, RecordType::AAAA, RecordType::MX];
        let domain_name = "example.com";
        let query = Query::new(domain_name, record_types);

        let lookup = lookup(&io_loop.handle(), query, server);
        let result = io_loop.run(lookup).unwrap();
        let response: Response = result;

        assert_eq!(response.server, Ipv4Addr::from_str("8.8.8.8").unwrap());
        assert_eq!(response.answers.len(), 2);
        if let RData::A(ip) = *response.answers[0].rdata() {
            assert_eq!(ip, Ipv4Addr::new(93, 184, 216, 34));
        } else {
            panic!("Not an A record");
        }
        if let RData::AAAA(ip) = *response.answers[1].rdata() {
            assert_eq!(
                ip,
                Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946)
            );
        } else {
            panic!("Not an AAAA record");
        }
    }
}
