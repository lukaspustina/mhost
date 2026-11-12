use std::time::Duration;

use crate::nameserver::NameServerConfig;
use crate::resolver::{MultiQuery, Resolver, ResolverConfig, ResolverOpts};
use crate::RecordType;

use super::fake_ns::FakeNs;

// With `tcp_fallback: false` a truncated UDP answer stays a truncation error and the TCP
// listener never sees a connection.
#[tokio::test]
async fn disabled_tcp_fallback_keeps_truncation_error_and_opens_no_tcp_connection() {
    let ns = FakeNs::start(true, vec!["first".to_string(), "second".to_string()]).await;

    let opts = ResolverOpts {
        timeout: Duration::from_secs(2),
        tcp_fallback: false,
        ..Default::default()
    };
    let resolver = Resolver::new(ResolverConfig::new(NameServerConfig::udp(ns.addr())), opts)
        .await
        .expect("resolver");
    let query = MultiQuery::single("example.com.", RecordType::TXT).expect("query");

    let lookups = tokio::time::timeout(Duration::from_secs(10), resolver.lookup(query))
        .await
        .expect("lookup finished")
        .expect("lookups");

    let lookup = lookups.iter().next().expect("one lookup");
    let err = lookup.result().err().expect("lookup is an error");
    assert!(err.to_string().contains("response was truncated"), "got {}", err);
    assert_eq!(ns.tcp_connections(), 0);
}
