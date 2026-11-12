use std::net::SocketAddr;

use crate::estimate::Estimate;
use crate::nameserver::NameServerConfig;
use crate::resolver::{MultiQuery, Resolver, ResolverConfig, ResolverOpts};
use crate::RecordType;

// A UDP resolver with TCP fallback may send each lookup twice per attempt (UDP, then TCP retry),
// so the maximum doubles; the minimum stays one request per lookup.
#[tokio::test]
async fn estimate_counts_tcp_retry() {
    let addr: SocketAddr = "127.0.0.1:5353".parse().unwrap();
    let cases = [
        (
            "1 name x 1 type, retries 0",
            0,
            vec!["a.example.com."],
            vec![RecordType::A],
            1,
            2,
        ),
        (
            "2 names x 3 types, retries 2",
            2,
            vec!["a.example.com.", "b.example.com."],
            vec![RecordType::A, RecordType::MX, RecordType::TXT],
            6,
            36,
        ),
    ];

    for (label, retries, names, types, min, max) in cases {
        let opts = ResolverOpts {
            retries,
            tcp_fallback: true,
            ..Default::default()
        };
        let resolver = Resolver::new(ResolverConfig::new(NameServerConfig::udp(addr)), opts)
            .await
            .expect("resolver");
        let query = MultiQuery::new(names, types).unwrap();

        let est = resolver.estimate(&query);

        assert_eq!(est.min_requests, min, "min, case: {label}");
        assert_eq!(est.max_requests, max, "max, case: {label}");
    }
}
