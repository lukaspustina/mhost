use std::net::SocketAddr;

use crate::estimate::Estimate;
use crate::nameserver::NameServerConfig;
use crate::resolver::{Mode, MultiQuery, Resolver, ResolverConfig, ResolverGroup, ResolverGroupOpts, ResolverOpts};
use crate::RecordType;

async fn resolver(config: NameServerConfig) -> Resolver {
    let opts = ResolverOpts {
        retries: 0,
        tcp_fallback: true,
        ..Default::default()
    };
    Resolver::new(ResolverConfig::new(config), opts)
        .await
        .expect("resolver")
}

// A group keeps its aggregation rules over the per-resolver estimates: `Multi` sums the resolvers,
// `Uni` takes the first. A udp resolver with fallback on may send one extra TCP request per lookup.
// Building resolvers does not connect, so no listener is needed.
#[tokio::test]
async fn group_estimate_counts_tcp_retry() {
    let addr: SocketAddr = "127.0.0.1:5353".parse().unwrap();
    let query = MultiQuery::single("example.com.", RecordType::A).unwrap();

    // (label, mode, resolvers, expected min, expected max)
    let cases = [
        (
            "multi: udp with fallback plus tcp",
            Mode::Multi,
            vec![NameServerConfig::udp(addr), NameServerConfig::tcp(addr)],
            2,
            3,
        ),
        (
            "uni: first resolver udp with fallback",
            Mode::Uni,
            vec![NameServerConfig::udp(addr), NameServerConfig::tcp(addr)],
            1,
            2,
        ),
    ];

    for (label, mode, configs, min, max) in cases {
        let mut resolvers = Vec::new();
        for config in configs {
            resolvers.push(resolver(config).await);
        }
        let group = ResolverGroup::new(
            resolvers,
            ResolverGroupOpts {
                mode,
                limit: None,
                ..Default::default()
            },
        );

        let est = group.estimate(&query);

        assert_eq!((est.min_requests, est.max_requests), (min, max), "case: {label}");
    }
}
