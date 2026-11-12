use std::time::Duration;

use crate::nameserver::NameServerConfig;
use crate::resolver::{MultiQuery, Resolver, ResolverConfig, ResolverOpts};
use crate::RecordType;

use super::fake_ns::FakeNs;

// A `udp:` nameserver whose UDP answer is truncated must be retried over TCP on the same
// address, so the lookup yields the full TXT set instead of a truncation error.
#[tokio::test]
async fn truncated_udp_answer_is_completed_over_tcp() {
    let expected = vec!["first".to_string(), "second".to_string(), "third".to_string()];
    let ns = FakeNs::start(true, expected.clone()).await;

    let opts = ResolverOpts {
        timeout: Duration::from_secs(2),
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
    assert!(lookup.result().is_response(), "got {:?}", lookup.result());
    let mut got: Vec<String> = lookups.txt().iter().map(|t| t.as_string()).collect();
    got.sort();
    assert_eq!(got, expected);
    assert_eq!(ns.tcp_connections(), 1);
}
