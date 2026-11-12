use crate::app::cli_parser::create_parser;
use crate::app::resolver::AppResolver;
use crate::app::AppConfig;
use crate::resolver::tcp_fallback_tests::fake_ns::FakeNs;
use crate::resolver::MultiQuery;
use crate::RecordType;

#[tokio::test]
async fn cli_udp_lookup_of_truncated_txt_returns_records_without_error() {
    let ns = FakeNs::start(true, vec!["one".to_string(), "two".to_string(), "three".to_string()]).await;
    let server = format!("udp:{}", ns.addr());
    let matches = create_parser()
        .try_get_matches_from(["mhost", "-S", "-s", &server, "lookup", "-t", "TXT", "example.com."])
        .expect("CLI arguments must parse");
    let config = AppConfig::try_from(&matches).expect("AppConfig must build");

    let resolver = AppResolver::create_resolvers(&config)
        .await
        .expect("resolvers must build");
    let query = MultiQuery::single("example.com.", RecordType::TXT).expect("query must build");
    let lookups = resolver.lookup(query).await.expect("lookup must complete");

    let errors: Vec<String> = lookups
        .iter()
        .filter_map(|l| l.result().err().map(|e| e.to_string()))
        .collect();
    assert!(errors.is_empty(), "lookup errors: {:?}", errors);

    let mut texts: Vec<String> = lookups
        .txt()
        .iter()
        .map(|t| {
            t.iter()
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .collect::<String>()
        })
        .collect();
    texts.sort();
    assert_eq!(texts, vec!["one", "three", "two"]);
}
