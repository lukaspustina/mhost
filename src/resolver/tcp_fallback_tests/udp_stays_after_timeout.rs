use std::net::IpAddr;
use std::time::Duration;

use crate::nameserver::NameServerConfig;
use crate::resolver::{MultiQuery, Resolver, ResolverConfig, ResolverOpts};
use crate::RecordType;

use super::fake_ns::{FakeNs, UdpBehavior};

// A UDP timeout must not push later queries of the same resolver onto TCP: only the truncated
// TXT query uses the TCP listener, and `A after.example.com.` is answered over UDP.
#[tokio::test]
async fn udp_timeout_does_not_move_later_queries_to_tcp() {
    let expected_txt = vec!["first".to_string(), "second".to_string()];
    let ns = FakeNs::builder()
        .udp_for("example.com.", UdpBehavior::Truncate)
        .udp_for("drop.example.com.", UdpBehavior::Drop)
        .txt_records(expected_txt.clone())
        .start()
        .await;

    let opts = ResolverOpts {
        timeout: Duration::from_millis(500),
        retries: 0,
        ..Default::default()
    };
    let resolver = Resolver::new(ResolverConfig::new(NameServerConfig::udp(ns.addr())), opts)
        .await
        .expect("resolver");

    let mut results = Vec::new();
    for (name, record_type) in [
        ("example.com.", RecordType::TXT),
        ("before.example.com.", RecordType::A),
        ("drop.example.com.", RecordType::A),
        ("after.example.com.", RecordType::A),
    ] {
        let query = MultiQuery::single(name, record_type).expect("query");
        let lookups = tokio::time::timeout(Duration::from_secs(10), resolver.lookup(query))
            .await
            .expect("lookup finished")
            .expect("lookups");
        results.push(lookups);
    }

    let mut txt: Vec<String> = results[0].txt().iter().map(|t| t.as_string()).collect();
    txt.sort();
    assert_eq!(txt, expected_txt);
    assert!(results[1].iter().next().expect("before").result().is_response());
    assert!(results[2].iter().next().expect("drop").result().is_err());
    let after = results[3].iter().next().expect("after");
    assert!(after.result().is_response(), "got {:?}", after.result());
    assert_eq!(after.ips(), vec!["192.0.2.1".parse::<IpAddr>().unwrap()]);

    assert_eq!(ns.tcp_queries(), vec![("example.com.".to_string(), "TXT".to_string())]);
    assert!(ns
        .udp_queries()
        .contains(&("after.example.com.".to_string(), "A".to_string())));
}
