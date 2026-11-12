use std::time::Duration;

use crate::nameserver::NameServerConfig;
use crate::resolver::{MultiQuery, Resolver, ResolverConfig, ResolverOpts};
use crate::RecordType;

use super::fake_ns::{FakeNs, UdpBehavior};

// Every lookup starts over UDP, also after an earlier truncated answer, and is repeated exactly
// once over TCP: two lookups yield two UDP queries and two TCP queries.
#[tokio::test]
async fn each_truncated_lookup_starts_over_udp_and_retries_once_over_tcp() {
    let expected = vec!["first".to_string(), "second".to_string()];
    let ns = FakeNs::builder()
        .udp_default(UdpBehavior::Truncate)
        .txt_records(expected.clone())
        .start()
        .await;

    let opts = ResolverOpts {
        timeout: Duration::from_secs(2),
        ..Default::default()
    };
    let resolver = Resolver::new(ResolverConfig::new(NameServerConfig::udp(ns.addr())), opts)
        .await
        .expect("resolver");
    assert!(resolver.tcp_retry.is_some());

    for round in 1..=2 {
        let query = MultiQuery::single("example.com.", RecordType::TXT).expect("query");
        let lookups = tokio::time::timeout(Duration::from_secs(10), resolver.lookup(query))
            .await
            .expect("lookup finished")
            .expect("lookups");

        let lookup = lookups.iter().next().expect("one lookup");
        assert!(
            lookup.result().is_response(),
            "round {round}: got {:?}",
            lookup.result()
        );
        let mut got: Vec<String> = lookups.txt().iter().map(|t| t.as_string()).collect();
        got.sort();
        assert_eq!(got, expected, "round {round}");
    }

    let txt = ("example.com.".to_string(), "TXT".to_string());
    assert_eq!(ns.udp_queries(), vec![txt.clone(), txt.clone()]);
    assert_eq!(ns.tcp_queries(), vec![txt.clone(), txt]);
}
