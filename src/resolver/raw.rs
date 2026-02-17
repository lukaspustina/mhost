// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Raw DNS query layer for non-recursive (RD=0) queries with full response access.
//!
//! Used by the trace command to perform iterative DNS resolution, querying
//! nameservers directly without recursion and inspecting authority/additional sections.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use futures::stream::{self, StreamExt};
use hickory_resolver::proto::op::{Message, MessageType, OpCode, Query};
use hickory_resolver::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_resolver::proto::serialize::binary::BinDecodable;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

/// Root DNS server IPv4 addresses (a.root-servers.net through m.root-servers.net).
pub static ROOT_SERVERS: &[Ipv4Addr] = &[
    Ipv4Addr::new(198, 41, 0, 4),     // a.root-servers.net
    Ipv4Addr::new(170, 247, 170, 2),  // b.root-servers.net
    Ipv4Addr::new(192, 33, 4, 12),    // c.root-servers.net
    Ipv4Addr::new(199, 7, 91, 13),    // d.root-servers.net
    Ipv4Addr::new(192, 203, 230, 10), // e.root-servers.net
    Ipv4Addr::new(192, 5, 5, 241),    // f.root-servers.net
    Ipv4Addr::new(192, 112, 36, 4),   // g.root-servers.net
    Ipv4Addr::new(198, 97, 190, 53),  // h.root-servers.net
    Ipv4Addr::new(192, 36, 148, 17),  // i.root-servers.net
    Ipv4Addr::new(192, 58, 128, 30),  // j.root-servers.net
    Ipv4Addr::new(193, 0, 14, 129),   // k.root-servers.net
    Ipv4Addr::new(199, 7, 83, 42),    // l.root-servers.net
    Ipv4Addr::new(202, 12, 27, 33),   // m.root-servers.net
];

/// Root DNS server IPv6 addresses (a.root-servers.net through m.root-servers.net).
pub static ROOT_SERVERS_V6: &[Ipv6Addr] = &[
    Ipv6Addr::new(0x2001, 0x0503, 0xba3e, 0, 0, 0, 0x0002, 0x0030), // a.root-servers.net
    Ipv6Addr::new(0x2801, 0x01b8, 0x0010, 0, 0, 0, 0, 0x000b),      // b.root-servers.net
    Ipv6Addr::new(0x2001, 0x0500, 0x0002, 0, 0, 0, 0, 0x000c),      // c.root-servers.net
    Ipv6Addr::new(0x2001, 0x0500, 0x002d, 0, 0, 0, 0, 0x000d),      // d.root-servers.net
    Ipv6Addr::new(0x2001, 0x0500, 0x00a8, 0, 0, 0, 0, 0x000e),      // e.root-servers.net
    Ipv6Addr::new(0x2001, 0x0500, 0x002f, 0, 0, 0, 0, 0x000f),      // f.root-servers.net
    Ipv6Addr::new(0x2001, 0x0500, 0x0012, 0, 0, 0, 0, 0x0d0d),      // g.root-servers.net
    Ipv6Addr::new(0x2001, 0x0500, 0x0001, 0, 0, 0, 0, 0x0053),      // h.root-servers.net
    Ipv6Addr::new(0x2001, 0x07fe, 0, 0, 0, 0, 0, 0x0053),           // i.root-servers.net
    Ipv6Addr::new(0x2001, 0x0503, 0x0c27, 0, 0, 0, 0x0002, 0x0030), // j.root-servers.net
    Ipv6Addr::new(0x2001, 0x07fd, 0, 0, 0, 0, 0, 0x0001),           // k.root-servers.net
    Ipv6Addr::new(0x2001, 0x0500, 0x009f, 0, 0, 0, 0, 0x0042),      // l.root-servers.net
    Ipv6Addr::new(0x2001, 0x0dc3, 0, 0, 0, 0, 0, 0x0035),           // m.root-servers.net
];

#[derive(Debug, Error)]
pub enum RawError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("DNS message decode error: {0}")]
    Decode(String),
    #[error("query timed out after {0:?}")]
    Timeout(Duration),
    #[error("response ID mismatch (expected {expected}, got {got})")]
    IdMismatch { expected: u16, got: u16 },
}

pub type RawResult<T> = std::result::Result<T, RawError>;

/// A parsed DNS response with full access to all sections.
#[derive(Debug, Clone)]
pub struct RawResponse {
    message: Message,
    latency: Duration,
}

impl RawResponse {
    #[cfg(test)]
    pub fn new_for_test(message: Message, latency: Duration) -> Self {
        RawResponse { message, latency }
    }

    pub fn answers(&self) -> &[Record] {
        self.message.answers()
    }

    pub fn authority(&self) -> &[Record] {
        self.message.name_servers()
    }

    pub fn additional(&self) -> &[Record] {
        self.message.additionals()
    }

    pub fn is_authoritative(&self) -> bool {
        self.message.authoritative()
    }

    pub fn is_truncated(&self) -> bool {
        self.message.truncated()
    }

    pub fn response_code(&self) -> hickory_resolver::proto::op::ResponseCode {
        self.message.response_code()
    }

    pub fn latency(&self) -> Duration {
        self.latency
    }

    /// Extract NS names from the authority section.
    pub fn referral_ns_names(&self) -> Vec<Name> {
        self.authority()
            .iter()
            .filter(|r| r.record_type() == RecordType::NS)
            .filter_map(|r| match r.data() {
                RData::NS(ns) => Some(ns.0.clone()),
                _ => None,
            })
            .collect()
    }

    /// Extract glue A/AAAA records from the additional section.
    pub fn glue_ips(&self) -> Vec<(Name, IpAddr)> {
        self.additional()
            .iter()
            .filter_map(|r| match r.data() {
                RData::A(a) => Some((r.name().clone(), IpAddr::V4(a.0))),
                RData::AAAA(aaaa) => Some((r.name().clone(), IpAddr::V6(aaaa.0))),
                _ => None,
            })
            .collect()
    }
}

/// Result of querying a single server — pairs the server address with outcome.
#[derive(Debug)]
pub struct RawQueryResult {
    pub server: SocketAddr,
    pub result: RawResult<RawResponse>,
}

/// Send a non-recursive DNS query to a single server over UDP, with automatic TCP fallback
/// on truncation.
pub async fn raw_query(
    server: SocketAddr,
    name: &Name,
    record_type: RecordType,
    timeout: Duration,
) -> RawResult<RawResponse> {
    let msg = build_query_message(name, record_type);
    let response = send_udp(server, &msg, timeout).await?;
    if response.is_truncated() {
        debug!("UDP response from {} truncated, retrying over TCP", server);
        let msg = build_query_message(name, record_type);
        send_tcp(server, &msg, timeout).await
    } else {
        Ok(response)
    }
}

/// Send non-recursive DNS queries to multiple servers in parallel.
pub async fn parallel_raw_queries(
    servers: &[SocketAddr],
    name: &Name,
    record_type: RecordType,
    timeout: Duration,
    max_concurrent: usize,
) -> Vec<RawQueryResult> {
    let futures = servers.iter().map(|&server| {
        let name = name.clone();
        async move {
            let result = raw_query(server, &name, record_type, timeout).await;
            RawQueryResult { server, result }
        }
    });

    stream::iter(futures).buffer_unordered(max_concurrent).collect().await
}

/// Send a non-recursive DNS query with the DNSSEC OK (DO) bit set, requesting
/// RRSIG and other DNSSEC records in responses.
pub async fn raw_dnssec_query(
    server: SocketAddr,
    name: &Name,
    record_type: RecordType,
    timeout: Duration,
) -> RawResult<RawResponse> {
    let msg = build_dnssec_query_message(name, record_type);
    let response = send_udp(server, &msg, timeout).await?;
    if response.is_truncated() {
        debug!("UDP DNSSEC response from {} truncated, retrying over TCP", server);
        let msg = build_dnssec_query_message(name, record_type);
        send_tcp(server, &msg, timeout).await
    } else {
        Ok(response)
    }
}

/// Send non-recursive DNS queries with the DNSSEC OK (DO) bit to multiple servers in parallel.
pub async fn parallel_raw_dnssec_queries(
    servers: &[SocketAddr],
    name: &Name,
    record_type: RecordType,
    timeout: Duration,
    max_concurrent: usize,
) -> Vec<RawQueryResult> {
    let futures = servers.iter().map(|&server| {
        let name = name.clone();
        async move {
            let result = raw_dnssec_query(server, &name, record_type, timeout).await;
            RawQueryResult { server, result }
        }
    });

    stream::iter(futures).buffer_unordered(max_concurrent).collect().await
}

fn build_query_message(name: &Name, record_type: RecordType) -> Message {
    build_query_message_opts(name, record_type, false)
}

fn build_dnssec_query_message(name: &Name, record_type: RecordType) -> Message {
    build_query_message_opts(name, record_type, true)
}

fn build_query_message_opts(name: &Name, record_type: RecordType, dnssec_ok: bool) -> Message {
    let mut msg = Message::new();
    msg.set_id(rand::random());
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(false);
    let mut query = Query::new();
    query.set_name(name.clone());
    query.set_query_type(record_type);
    query.set_query_class(DNSClass::IN);
    msg.add_query(query);
    if dnssec_ok {
        let mut edns = hickory_resolver::proto::op::Edns::new();
        edns.set_dnssec_ok(true);
        edns.set_max_payload(4096);
        msg.set_edns(edns);
    }
    msg
}

async fn send_udp(server: SocketAddr, msg: &Message, timeout: Duration) -> RawResult<RawResponse> {
    let msg_bytes = msg.to_vec().map_err(|e| RawError::Decode(e.to_string()))?;
    let expected_id = msg.id();

    let bind_addr: SocketAddr = if server.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let socket = UdpSocket::bind(bind_addr).await?;

    let start = Instant::now();
    socket.send_to(&msg_bytes, server).await?;

    let mut buf = vec![0u8; 4096];
    let len = match tokio::time::timeout(timeout, socket.recv(&mut buf)).await {
        Ok(Ok(len)) => len,
        Ok(Err(e)) => return Err(RawError::Io(e)),
        Err(_) => return Err(RawError::Timeout(timeout)),
    };
    let latency = start.elapsed();

    let response = Message::from_bytes(&buf[..len]).map_err(|e| RawError::Decode(e.to_string()))?;
    if response.id() != expected_id {
        return Err(RawError::IdMismatch {
            expected: expected_id,
            got: response.id(),
        });
    }

    Ok(RawResponse {
        message: response,
        latency,
    })
}

async fn send_tcp(server: SocketAddr, msg: &Message, timeout: Duration) -> RawResult<RawResponse> {
    let msg_bytes = msg.to_vec().map_err(|e| RawError::Decode(e.to_string()))?;
    let expected_id = msg.id();

    let start = Instant::now();
    let mut stream = match tokio::time::timeout(timeout, TcpStream::connect(server)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(RawError::Io(e)),
        Err(_) => return Err(RawError::Timeout(timeout)),
    };

    // DNS over TCP: 2-byte length prefix
    let len = msg_bytes.len() as u16;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&msg_bytes).await?;

    // DNS over TCP responses use a 2-byte length prefix (max 65535).
    // Cap at 16KB to limit allocation from untrusted servers; standard DNS
    // responses rarely exceed a few KB outside of zone transfers (AXFR).
    const MAX_TCP_RESPONSE_LEN: usize = 16_384;

    let response_len = match tokio::time::timeout(timeout, stream.read_u16()).await {
        Ok(Ok(len)) => len as usize,
        Ok(Err(e)) => return Err(RawError::Io(e)),
        Err(_) => return Err(RawError::Timeout(timeout)),
    };

    if response_len > MAX_TCP_RESPONSE_LEN {
        return Err(RawError::Decode(format!(
            "TCP response length {} exceeds maximum {}",
            response_len, MAX_TCP_RESPONSE_LEN
        )));
    }

    let mut buf = vec![0u8; response_len];
    match tokio::time::timeout(timeout, stream.read_exact(&mut buf)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(RawError::Io(e)),
        Err(_) => return Err(RawError::Timeout(timeout)),
    };
    let latency = start.elapsed();

    let response = Message::from_bytes(&buf).map_err(|e| RawError::Decode(e.to_string()))?;
    if response.id() != expected_id {
        return Err(RawError::IdMismatch {
            expected: expected_id,
            got: response.id(),
        });
    }

    Ok(RawResponse {
        message: response,
        latency,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_query_message_sets_rd_false() {
        let name = Name::from_ascii("example.com.").unwrap();
        let msg = build_query_message(&name, RecordType::A);

        assert!(!msg.recursion_desired());
        assert_eq!(msg.op_code(), OpCode::Query);
        assert_eq!(msg.message_type(), MessageType::Query);
        assert_eq!(msg.queries().len(), 1);
        assert_eq!(msg.queries()[0].name(), &name);
        assert_eq!(msg.queries()[0].query_type(), RecordType::A);
        assert_eq!(msg.queries()[0].query_class(), DNSClass::IN);
    }

    #[test]
    fn root_servers_count() {
        assert_eq!(ROOT_SERVERS.len(), 13);
    }

    #[test]
    fn root_servers_v6_count() {
        assert_eq!(ROOT_SERVERS_V6.len(), 13);
    }

    #[test]
    fn raw_response_referral_ns_names() {
        let mut msg = Message::new();
        msg.set_id(1);
        msg.set_message_type(MessageType::Response);

        let ns_record = Record::from_rdata(
            Name::from_ascii("com.").unwrap(),
            172800,
            RData::NS(hickory_resolver::proto::rr::rdata::NS(
                Name::from_ascii("a.gtld-servers.net.").unwrap(),
            )),
        );
        msg.add_name_server(ns_record);

        let response = RawResponse {
            message: msg,
            latency: Duration::from_millis(10),
        };

        let ns_names = response.referral_ns_names();
        assert_eq!(ns_names.len(), 1);
        assert_eq!(ns_names[0], Name::from_ascii("a.gtld-servers.net.").unwrap());
    }

    #[test]
    fn raw_response_glue_ips() {
        let mut msg = Message::new();
        msg.set_id(1);
        msg.set_message_type(MessageType::Response);

        let a_record = Record::from_rdata(
            Name::from_ascii("a.gtld-servers.net.").unwrap(),
            172800,
            RData::A(hickory_resolver::proto::rr::rdata::A(Ipv4Addr::new(192, 5, 6, 30))),
        );
        msg.add_additional(a_record);

        let response = RawResponse {
            message: msg,
            latency: Duration::from_millis(10),
        };

        let glue = response.glue_ips();
        assert_eq!(glue.len(), 1);
        assert_eq!(glue[0].0, Name::from_ascii("a.gtld-servers.net.").unwrap());
        assert_eq!(glue[0].1, IpAddr::V4(Ipv4Addr::new(192, 5, 6, 30)));
    }

    #[test]
    fn raw_response_is_authoritative() {
        let mut msg = Message::new();
        msg.set_authoritative(true);
        let response = RawResponse {
            message: msg,
            latency: Duration::from_millis(5),
        };
        assert!(response.is_authoritative());
    }
}
