use std::time::Duration;

use crate::nameserver::NameServerConfig;
use crate::resolver::{MultiQuery, Resolver, ResolverConfig, ResolverOpts};
use crate::RecordType;

use super::fake_ns::{FakeNs, TcpMode, UdpBehavior};

// Without `tcp_fallback`, or for a `tcp:` nameserver, no TCP retry resolver exists: a truncated
// UDP answer ends in the plain truncation error and the TCP listener sees no query.
#[tokio::test]
async fn no_tcp_retry_resolver_without_fallback_or_for_tcp_nameserver() {
    let ns = FakeNs::builder()
        .udp_default(UdpBehavior::Truncate)
        .txt_records(vec!["first".to_string()])
        .tcp(TcpMode::Answer)
        .start()
        .await;

    let opts = ResolverOpts {
        timeout: Duration::from_secs(2),
        retries: 0,
        tcp_fallback: false,
        ..Default::default()
    };
    let resolver = Resolver::new(ResolverConfig::new(NameServerConfig::udp(ns.addr())), opts)
        .await
        .expect("resolver");
    assert!(resolver.tcp_retry.is_none());

    let query = MultiQuery::single("example.com.", RecordType::TXT).expect("query");
    let lookups = tokio::time::timeout(Duration::from_secs(10), resolver.lookup(query))
        .await
        .expect("lookup finished")
        .expect("lookups");
    let lookup = lookups.iter().next().expect("one lookup");
    let text = lookup.result().err().expect("lookup is an error").to_string();
    assert!(
        text.contains("response was truncated; TCP already tried or no other transport available"),
        "got {text}"
    );
    assert!(!text.contains("TCP retry failed"), "got {text}");
    assert!(ns.tcp_queries().is_empty());

    let tcp_resolver = Resolver::new(
        ResolverConfig::new(NameServerConfig::tcp(ns.addr())),
        ResolverOpts {
            tcp_fallback: true,
            ..Default::default()
        },
    )
    .await
    .expect("resolver");
    assert!(tcp_resolver.tcp_retry.is_none());
}
