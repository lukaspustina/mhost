use std::time::{Duration, Instant};
use std::{env, io};

use mhost::nameserver::NameServerConfigGroup;
use mhost::output::summary::SummaryOptions;
use mhost::output::{Output, OutputConfig, OutputFormat};
use mhost::resolver::{MultiQuery, ResolverConfigGroup, ResolverGroup, ResolverGroupOpts, ResolverOpts};
use mhost::statistics::Statistics;
use mhost::RecordType;

#[tokio::main]
async fn main() {
    let path = env::args()
        .nth(1)
        .unwrap_or_else(|| "contrib/resolvers.txt".to_string());
    let name = env::args().nth(2).unwrap_or_else(|| "www.example.com".to_string());

    let system_resolvers = ResolverGroup::from_system_config(Default::default())
        .await
        .expect("failed to create system resolvers");

    let configs = NameServerConfigGroup::from_file(&system_resolvers, path)
        .await
        .expect("failed to read name server configs from file");
    println!("Loaded {} name servers", configs.len());
    let resolver_configs: ResolverConfigGroup = configs.into();

    let resolver_opts = ResolverOpts {
        attempts: 1,
        max_concurrent_requests: 20,
        timeout: Duration::from_secs(1),
        ..Default::default()
    };
    let group_opts = ResolverGroupOpts { max_concurrent: 1000 };

    let resolvers = ResolverGroup::from_configs(resolver_configs, resolver_opts, group_opts)
        .await
        .expect("failed to create resolvers");
    println!("Created {} resolvers", resolvers.len());

    let mq = MultiQuery::multi_record(name, vec![RecordType::A, RecordType::AAAA, RecordType::TXT])
        .expect("Failed to create multi-query");

    let start_time = Instant::now();
    let lookups = resolvers.lookup(mq).await;
    let total_run_time = Instant::now() - start_time;

    let statistics = lookups.statistics();
    println!(
        "Received {} within {} ms of total run time.",
        statistics,
        total_run_time.as_millis()
    );

    let stdout = io::stdout();
    let mut handle = stdout.lock();

    let opts = SummaryOptions::default();
    let config = OutputConfig::summary(opts);
    let output = Output::new(config);
    output
        .output(&mut handle, &lookups)
        .expect("failed to serialize to stdout");
}
