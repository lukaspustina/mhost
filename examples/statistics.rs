use std::env;
use std::time::Instant;

use mhost::resolver::{MultiQuery, ResolverGroup};
use mhost::statistics::Statistics;
use mhost::RecordType;

#[tokio::main]
async fn main() {
    let name = env::args().nth(1).unwrap_or_else(|| "www.example.com".to_string());

    let resolvers = ResolverGroup::from_system_config(Default::default())
        .await
        .expect("failed to create system resolvers");

    let mq = MultiQuery::multi_record(name, vec![RecordType::A, RecordType::AAAA, RecordType::TXT])
        .expect("failed to create multi-query");
    let start_time = Instant::now();
    let lookups = resolvers.lookup(mq).await;
    let total_run_time = Instant::now() - start_time;

    //println!("Multi-Lookup results: {:#?}", lookups);

    let successes = lookups.iter().filter(|x| x.result().is_response()).count();
    println!("Multi-Lookup successful results: {}/{}", successes, lookups.len());

    let failures: Vec<_> = lookups.iter().filter(|x| !x.result().is_response()).collect();
    println!("Multi-Lookup failed results: {:#?}", failures.len());

    let statistics = lookups.statistics();
    println!("Statistics: {:#?}", statistics);

    println!(
        "Received {} within {} ms of total run time.",
        statistics,
        total_run_time.as_millis()
    );
}
