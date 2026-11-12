use std::net::SocketAddr;

use crate::estimate::Estimate;
use crate::nameserver::NameServerConfig;
use crate::resolver::{MultiQuery, Resolver, ResolverConfig, ResolverOpts};
use crate::RecordType;

// `min_requests` is names * record_types for every resolver; only a udp resolver with a TCP retry
// doubles its `max_requests`. The query has 2 names and 3 types; retries are 2.
#[tokio::test]
async fn estimate_min_unchanged_max_doubles_only_with_tcp_retry() {
    let addr: SocketAddr = "127.0.0.1:5353".parse().unwrap();
    let query = MultiQuery::new(
        vec!["a.example.com.", "b.example.com."],
        vec![RecordType::A, RecordType::MX, RecordType::TXT],
    )
    .unwrap();
    // (label, config, tcp_fallback, expected min, expected max)
    let cases = [
        ("udp, fallback on", NameServerConfig::udp(addr), true, 6, 36),
        ("udp, fallback off", NameServerConfig::udp(addr), false, 6, 18),
        ("tcp, fallback on", NameServerConfig::tcp(addr), true, 6, 18),
        ("tcp, fallback off", NameServerConfig::tcp(addr), false, 6, 18),
    ];

    for (label, config, tcp_fallback, expected_min, expected_max) in cases {
        let opts = ResolverOpts {
            tcp_fallback,
            retries: 2,
            ..Default::default()
        };
        let resolver = Resolver::new(ResolverConfig::new(config), opts)
            .await
            .expect("resolver");

        let est = resolver.estimate(&query);

        assert_eq!(est.min_requests, expected_min, "min, case: {label}");
        assert_eq!(est.max_requests, expected_max, "max, case: {label}");
    }
}
