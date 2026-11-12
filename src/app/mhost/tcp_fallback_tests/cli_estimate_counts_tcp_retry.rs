use crate::app::cli_parser::create_parser;
use crate::app::resolver::AppResolver;
use crate::app::AppConfig;
use crate::estimate::Estimate;
use crate::resolver::MultiQuery;
use crate::RecordType;

// The console line reads "between {min} and {max} requests" when min != max, so the
// expected line "between 1 and 2 requests" needs min == 1 and max == 2.
#[tokio::test]
async fn cli_udp_lookup_estimate_counts_the_tcp_retry() {
    let matches = create_parser()
        .try_get_matches_from([
            "mhost",
            "--no-system-lookups",
            "-s",
            "udp:127.0.0.1:53",
            "lookup",
            "-t",
            "A",
            "example.com.",
        ])
        .expect("CLI arguments must parse");
    let config = AppConfig::try_from(&matches).expect("AppConfig must build");

    let resolver = AppResolver::create_resolvers(&config)
        .await
        .expect("resolvers must build");
    let query = MultiQuery::single("example.com.", RecordType::A).expect("query must build");
    let estimate = resolver.resolvers().estimate(&query);

    assert_eq!((estimate.min_requests, estimate.max_requests), (1, 2));
}
