use std::net::SocketAddr;

use crate::nameserver::NameServerConfig;
use crate::resolver::{Resolver, ResolverConfig, ResolverOpts};

// A `Resolver` carries a TCP retry resolver iff its nameserver is `udp:` and `tcp_fallback` is on.
// Building does not connect, so no listener is needed.
#[tokio::test]
async fn tcp_retry_present_only_for_udp_with_fallback() {
    let addr: SocketAddr = "127.0.0.1:5353".parse().unwrap();
    let cases = [
        ("udp, fallback on", NameServerConfig::udp(addr), true, true),
        ("udp, fallback off", NameServerConfig::udp(addr), false, false),
        ("tcp, fallback on", NameServerConfig::tcp(addr), true, false),
        ("tcp, fallback off", NameServerConfig::tcp(addr), false, false),
    ];

    for (label, config, tcp_fallback, expected) in cases {
        let opts = ResolverOpts {
            tcp_fallback,
            ..Default::default()
        };
        let resolver = Resolver::new(ResolverConfig::new(config), opts)
            .await
            .expect("resolver");

        assert_eq!(resolver.tcp_retry.is_some(), expected, "case: {label}");
    }
}
