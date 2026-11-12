use std::time::Duration;

use crate::nameserver::NameServerConfig;
use crate::resolver::{Error, MultiQuery, Resolver, ResolverConfig, ResolverOpts};
use crate::RecordType;

use super::fake_ns::{FakeNs, TcpMode, UdpBehavior};

// A truncated UDP answer whose TCP retry is refused (no listener) must end in a resolve error that
// names both causes, not in a bare truncation error or a timeout.
#[tokio::test]
async fn refused_tcp_retry_reports_truncation_and_retry_failure() {
    let ns = FakeNs::builder()
        .udp_default(UdpBehavior::Truncate)
        .txt_records(vec!["first".to_string(), "second".to_string()])
        .tcp(TcpMode::NoListener)
        .start()
        .await;

    let opts = ResolverOpts {
        timeout: Duration::from_secs(1),
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
    match lookup.result().err().expect("lookup is an error") {
        Error::ResolveError { reason } => assert!(
            reason.starts_with("response was truncated; TCP retry failed: "),
            "got {}",
            reason
        ),
        other => panic!("expected ResolveError, got {:?}", other),
    }
}
