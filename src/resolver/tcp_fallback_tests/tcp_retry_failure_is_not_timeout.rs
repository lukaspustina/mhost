use std::time::Duration;

use crate::nameserver::NameServerConfig;
use crate::resolver::lookup::LookupResult;
use crate::resolver::{Error, MultiQuery, Resolver, ResolverConfig, ResolverOpts};
use crate::statistics::Statistics;
use crate::RecordType;

use super::fake_ns::{FakeNs, TcpMode, UdpBehavior};

// A failed TCP retry is an "other" error, not a timeout, even when the cause is a TCP timeout:
// the lookup carries the prefixed ResolveError, statistics count it as non-timeout, and the
// abort-on-timeout breaker does not stop the second query (concurrency 1 makes it sequential).
#[tokio::test]
async fn failed_tcp_retry_is_other_error_and_does_not_trip_timeout_breaker() {
    let ns = FakeNs::builder()
        .udp_for("example.com.", UdpBehavior::Truncate)
        .tcp(TcpMode::Silent)
        .start()
        .await;

    let opts = ResolverOpts {
        timeout: Duration::from_secs(1),
        retries: 0,
        abort_on_timeout: true,
        max_concurrent_requests: 1,
        tcp_fallback: true,
        ..Default::default()
    };
    let resolver = Resolver::new(ResolverConfig::new(NameServerConfig::udp(ns.addr())), opts)
        .await
        .expect("resolver");
    let query = MultiQuery::multi_name(vec!["example.com.", "second.example.com."], RecordType::TXT).expect("query");

    let lookups = tokio::time::timeout(Duration::from_secs(20), resolver.lookup(query))
        .await
        .expect("lookup finished")
        .expect("lookups");

    assert_eq!(lookups.len(), 2, "breaker must not stop the second query");

    let truncated = lookups
        .iter()
        .find(|l| l.query().name().to_string() == "example.com.")
        .expect("truncated lookup");
    match truncated.result() {
        LookupResult::Error(Error::ResolveError { reason }) => assert!(
            reason.starts_with("response was truncated; TCP retry failed: "),
            "got {reason:?}"
        ),
        other => panic!("expected ResolveError, got {other:?}"),
    }

    let second = lookups
        .iter()
        .find(|l| l.query().name().to_string() == "second.example.com.")
        .expect("second lookup");
    assert!(second.result().is_response(), "got {:?}", second.result());

    let stats = lookups.statistics();
    assert_eq!(stats.timeout_errors, 0);
    assert_eq!(stats.total_errors, 1);
}
