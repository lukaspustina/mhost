#![cfg(feature = "app-cli")]

use std::time::Duration;

use hickory_resolver::proto::rr::{Name, RData, RecordType};

use crate::resolver::raw::raw_query;

use super::fake_ns::{FakeNs, TcpMode, UdpBehavior};

// With `tcp_fallback = true`, a truncated UDP answer to a raw query is retried over TCP, so the
// complete TXT set arrives and exactly one TCP connection was opened.
#[tokio::test]
async fn raw_query_with_fallback_completes_truncated_answer_over_tcp() {
    let expected = vec!["first".to_string(), "second".to_string(), "third".to_string()];
    let ns = FakeNs::builder()
        .udp_default(UdpBehavior::Truncate)
        .tcp(TcpMode::Answer)
        .txt_records(expected.clone())
        .start()
        .await;
    let name: Name = "example.com.".parse().expect("name");

    let response = tokio::time::timeout(
        Duration::from_secs(10),
        raw_query(ns.addr(), &name, RecordType::TXT, Duration::from_secs(2), true),
    )
    .await
    .expect("raw query finished")
    .expect("response");

    assert!(!response.is_truncated());
    let mut got: Vec<String> = response
        .answers()
        .iter()
        .map(|r| match &r.data {
            RData::TXT(txt) => txt
                .txt_data
                .iter()
                .map(|part| String::from_utf8_lossy(part).into_owned())
                .collect::<String>(),
            other => panic!("unexpected answer {:?}", other),
        })
        .collect();
    got.sort();
    assert_eq!(got, expected);
    assert_eq!(ns.tcp_connections(), 1);
    assert_eq!(ns.udp_queries().len(), 1);
    assert_eq!(ns.tcp_queries().len(), 1);
}
