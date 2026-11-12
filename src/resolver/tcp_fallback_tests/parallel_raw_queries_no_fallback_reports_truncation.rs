#![cfg(feature = "app-cli")]

use std::time::Duration;

use hickory_resolver::proto::rr::{Name, RecordType};

use crate::resolver::raw::{parallel_raw_queries, RawError};

use super::fake_ns::FakeNs;

// With `tcp_fallback` false the truncating server's entry is `RawError::Truncated` and no TCP
// connection is opened.
#[tokio::test]
async fn parallel_raw_queries_without_tcp_fallback_reports_truncation_and_opens_no_tcp_connection() {
    let ns = FakeNs::start(true, vec!["full".to_string()]).await;
    let name = Name::from_ascii("example.com.").expect("name");

    let results = tokio::time::timeout(
        Duration::from_secs(10),
        parallel_raw_queries(&[ns.addr()], &name, RecordType::TXT, Duration::from_secs(2), 4, false),
    )
    .await
    .expect("queries finished");

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].server, ns.addr());
    assert!(
        matches!(&results[0].result, Err(RawError::Truncated { server }) if *server == ns.addr()),
        "got {:?}",
        results[0].result
    );
    assert_eq!(ns.tcp_connections(), 0);
}
