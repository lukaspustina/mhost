use std::time::Duration;

use crate::nameserver::NameServerConfig;
use crate::resolver::{MultiQuery, Resolver, ResolverConfig, ResolverOpts};
use crate::RecordType;

use super::fake_ns::FakeNs;

// With TCP configured as fallback, a complete (non-truncated) UDP answer must stay on UDP:
// the TCP listener sees no connection and the records arrive intact.
#[tokio::test]
async fn complete_udp_answer_opens_no_tcp_connection() {
    let expected = vec!["first".to_string(), "second".to_string()];
    let ns = FakeNs::start(false, expected.clone()).await;

    let opts = ResolverOpts {
        timeout: Duration::from_secs(2),
        tcp_fallback: true,
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
    assert_eq!(ns.tcp_connections(), 0);
}
