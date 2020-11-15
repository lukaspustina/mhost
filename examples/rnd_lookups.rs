use std::time::Instant;
use std::{env, io};

use mhost::output::summary::SummaryOptions;
use mhost::output::{Output, OutputConfig, OutputFormat};
use mhost::resolver::{predefined, MultiQuery, ResolverGroup};
use mhost::statistics::Statistics;
use mhost::RecordType;

#[tokio::main]
async fn main() {
    let name = env::args().nth(1).unwrap_or_else(|| "www.example.com".to_string());

    let resolver_configs = predefined::resolver_configs();
    let resolvers = ResolverGroup::from_configs(resolver_configs, Default::default(), Default::default())
        .await
        .expect("failed to create resolvers");

    let mq = MultiQuery::multi_record(
        name,
        vec![
            RecordType::A,
            RecordType::AAAA,
            RecordType::ANAME,
            RecordType::CNAME,
            RecordType::MX,
            RecordType::NULL,
            RecordType::NS,
            RecordType::PTR,
            RecordType::SOA,
            RecordType::SRV,
            RecordType::TXT,
        ],
    )
    .expect("Failed to create multi-query");
    let start_time = Instant::now();
    let lookups = resolvers
        .single_server_lookup(mq)
        .await
        .expect("failed to execute lookups");
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
    let output = Output::new(&config);
    output
        .output(&mut handle, &lookups)
        .expect("failed to serialize to stdout");
}
