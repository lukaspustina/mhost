#![cfg(feature = "app-cli")]

use std::time::Duration;

use hickory_resolver::proto::rr::{Name, RecordType};

use crate::resolver::raw::{raw_query, RawError};

use super::fake_ns::FakeNs;

// With `tcp_fallback` false a truncated UDP answer is `RawError::Truncated` and no TCP
// connection is opened.
#[tokio::test]
async fn raw_query_without_tcp_fallback_reports_truncation_and_opens_no_tcp_connection() {
    let ns = FakeNs::start(true, vec!["full".to_string()]).await;
    let name = Name::from_ascii("example.com.").expect("name");

    let err = tokio::time::timeout(
        Duration::from_secs(10),
        raw_query(ns.addr(), &name, RecordType::TXT, Duration::from_secs(2), false),
    )
    .await
    .expect("query finished")
    .expect_err("truncated answer is an error");

    assert!(
        matches!(&err, RawError::Truncated { server } if *server == ns.addr()),
        "got {:?}",
        err
    );
    assert_eq!(
        err.to_string(),
        format!("response from {} was truncated and TCP fallback is disabled", ns.addr())
    );
    assert_eq!(ns.tcp_connections(), 0);
}
