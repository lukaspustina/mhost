use crate::app::cli_parser::create_parser;
use crate::app::resolver::AppResolver;
use crate::app::AppConfig;
use crate::estimate::Estimate;
use crate::resolver::MultiQuery;
use crate::RecordType;

// With `--no-tcp-fallback` a single A lookup against one UDP nameserver is estimated at exactly
// one request (min 1, max 1), which the console prints as "1 request". No TCP retry is counted.
#[tokio::test]
async fn no_tcp_fallback_estimate_is_one_request() {
    let matches = create_parser()
        .try_get_matches_from([
            "mhost",
            "--no-system-lookups",
            "--no-tcp-fallback",
            "-s",
            "udp:127.0.0.1:5353",
            "lookup",
            "-t",
            "A",
            "example.com",
        ])
        .expect("CLI arguments must parse");
    let config = AppConfig::try_from(&matches).expect("AppConfig must build");
    let resolvers = AppResolver::create_resolvers(&config).await.expect("resolvers");
    let query = MultiQuery::single("example.com.", RecordType::A).expect("query");

    let estimate = resolvers.resolvers().estimate(&query);

    assert_eq!((estimate.min_requests, estimate.max_requests), (1, 1));
}
