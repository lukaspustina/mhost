use std::time::Duration;

use crate::app::cli_parser::create_parser;
use crate::app::resolver::AppResolver;
use crate::app::AppConfig;
use crate::resolver::tcp_fallback_tests::fake_ns::FakeNs;
use crate::resolver::MultiQuery;
use crate::RecordType;

// `--no-tcp-fallback` given to the CLI leaves a truncated UDP answer as it is: the lookup holds
// a "response was truncated" error, no TXT record, and the nameserver never sees a TCP connection.
#[tokio::test]
async fn no_tcp_fallback_flag_surfaces_truncated_response() {
    let ns = FakeNs::start(true, vec!["first".into(), "second".into(), "third".into()]).await;
    let server = format!("udp:{}", ns.addr());

    let matches = create_parser()
        .try_get_matches_from([
            "mhost",
            "--no-tcp-fallback",
            "-S",
            "-s",
            server.as_str(),
            "lookup",
            "-t",
            "TXT",
            "example.com.",
        ])
        .expect("CLI arguments must parse");
    let config = AppConfig::try_from(&matches).expect("AppConfig must build");
    let resolver = AppResolver::create_resolvers(&config).await.expect("resolvers");
    let query = MultiQuery::single("example.com.", RecordType::TXT).expect("query");

    let lookups = tokio::time::timeout(Duration::from_secs(10), resolver.lookup(query))
        .await
        .expect("lookup finished")
        .expect("lookups");

    let errors: Vec<String> = lookups
        .iter()
        .filter_map(|l| l.result().err().map(|e| e.to_string()))
        .collect();
    assert!(
        errors.iter().any(|e| e.contains("response was truncated")),
        "errors: {errors:?}"
    );
    assert!(lookups.txt().is_empty());
    assert_eq!(ns.tcp_connections(), 0);
}
