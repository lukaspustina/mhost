#![cfg(feature = "app-cli")]

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Duration;

use hickory_resolver::proto::rr::{Name, RData, RecordType};

use crate::resolver::raw::raw_query;

use super::fake_ns::{FakeNs, UdpBehavior};

// A complete (non-truncated) UDP answer is returned unchanged and opens no TCP connection,
// whatever `tcp_fallback` (the last `raw_query` parameter) says.
#[tokio::test]
async fn raw_complete_udp_answer_opens_no_tcp_connection() {
    let name = Name::from_str("example.com.").expect("name");

    for tcp_fallback in [false, true] {
        let ns = FakeNs::builder().udp_default(UdpBehavior::Answer).start().await;

        let response = tokio::time::timeout(
            Duration::from_secs(10),
            raw_query(ns.addr(), &name, RecordType::A, Duration::from_secs(2), tcp_fallback),
        )
        .await
        .expect("query finished")
        .expect("response");

        assert!(!response.is_truncated(), "tcp_fallback={tcp_fallback}");
        let addrs: Vec<Ipv4Addr> = response
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
            .collect();
        assert_eq!(addrs, vec![Ipv4Addr::new(192, 0, 2, 1)], "tcp_fallback={tcp_fallback}");
        assert_eq!(ns.tcp_connections(), 0, "tcp_fallback={tcp_fallback}");
    }
}
