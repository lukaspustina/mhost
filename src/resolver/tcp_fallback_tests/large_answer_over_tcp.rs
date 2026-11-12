use std::time::Duration;

use crate::nameserver::NameServerConfig;
use crate::resolver::{MultiQuery, Resolver, ResolverConfig, ResolverOpts};
use crate::RecordType;

use super::fake_ns::FakeNs;

// A realistic large TXT answer (62 records of 70 bytes, well above 4096 bytes in total) that
// the UDP path truncates must arrive complete over TCP with default options, without error.
#[tokio::test]
async fn large_truncated_txt_answer_arrives_complete_over_tcp() {
    let expected: Vec<String> = (0..62)
        .map(|i| format!("v=spf1 record-{i:02} {}", "x".repeat(53)))
        .collect();
    assert!(expected.iter().all(|t| t.len() == 70));
    let ns = FakeNs::start(true, expected.clone()).await;

    let opts = ResolverOpts {
        timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let resolver = Resolver::new(ResolverConfig::new(NameServerConfig::udp(ns.addr())), opts)
        .await
        .expect("resolver");
    let query = MultiQuery::single("example.com.", RecordType::TXT).expect("query");

    let lookups = tokio::time::timeout(Duration::from_secs(15), resolver.lookup(query))
        .await
        .expect("lookup finished")
        .expect("lookups");

    let lookup = lookups.iter().next().expect("one lookup");
    assert!(lookup.result().is_response(), "got {:?}", lookup.result());
    let mut got: Vec<String> = lookups.txt().iter().map(|t| t.as_string()).collect();
    got.sort();
    assert_eq!(got.len(), 62);
    assert_eq!(got, expected);
}
