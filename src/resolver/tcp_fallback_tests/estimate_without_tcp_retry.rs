use std::net::SocketAddr;

use crate::estimate::Estimate;
use crate::nameserver::NameServerConfig;
use crate::resolver::{MultiQuery, Resolver, ResolverConfig, ResolverOpts};
use crate::RecordType;

// A resolver without a TCP retry resolver keeps `max = names * record_types * (1 + retries)`:
// no second request per lookup is budgeted. Building does not connect, so no listener is needed.
#[tokio::test]
async fn estimate_without_tcp_retry_is_not_doubled() {
    let addr: SocketAddr = "127.0.0.1:5353".parse().unwrap();
    let cases = [
        ("udp, fallback off, retries 2", NameServerConfig::udp(addr), false, 2, 3),
        ("tcp, fallback on, retries 1", NameServerConfig::tcp(addr), true, 1, 2),
    ];

    for (label, config, tcp_fallback, retries, expected_max) in cases {
        let opts = ResolverOpts {
            tcp_fallback,
            retries,
            ..Default::default()
        };
        let resolver = Resolver::new(ResolverConfig::new(config), opts)
            .await
            .expect("resolver");
        assert!(resolver.tcp_retry.is_none(), "case: {label}");

        let query = MultiQuery::single("example.com.", RecordType::A).expect("query");
        let estimation = resolver.estimate(&query);

        assert_eq!(estimation.min_requests, 1, "case: {label}");
        assert_eq!(estimation.max_requests, expected_max, "case: {label}");
    }
}
