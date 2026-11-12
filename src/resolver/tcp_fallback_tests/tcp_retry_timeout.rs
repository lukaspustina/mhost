use std::time::Duration;

use crate::nameserver::NameServerConfig;
use crate::resolver::error::Error;
use crate::resolver::{MultiQuery, Resolver, ResolverConfig, ResolverOpts};
use crate::RecordType;

use super::fake_ns::{FakeNs, TcpMode, UdpBehavior};

// When the TCP retry of a truncated answer times out, the error names the truncation and the TCP
// failure, and is a `ResolveError`, not a plain `Timeout`.
#[tokio::test]
async fn tcp_retry_timeout_reports_truncation_not_timeout() {
    let ns = FakeNs::builder()
        .udp_default(UdpBehavior::Truncate)
        .txt_records(vec!["first".to_string()])
        .tcp(TcpMode::Silent)
        .start()
        .await;

    let opts = ResolverOpts {
        timeout: Duration::from_secs(1),
        retries: 0,
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

    let err = lookups
        .iter()
        .next()
        .expect("one lookup")
        .result()
        .err()
        .expect("lookup failed");
    match err {
        Error::ResolveError { reason } => assert!(
            reason.starts_with("response was truncated; TCP retry failed: request timed out"),
            "got {reason:?}"
        ),
        other => panic!("expected ResolveError, got {other:?}"),
    }
}
