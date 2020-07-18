use std::env;
use std::time::Instant;

use mhost::resolver::ResolverGroup;
use mhost::statistics::Statistics;
use mhost::{MultiQuery, RecordType};

#[tokio::main]
async fn main() {
    let name = env::args()
        .skip(1)
        .next()
        .unwrap_or_else(|| "www.example.com".to_string());

    let resolvers = ResolverGroup::from_system_config(Default::default())
        .await
        .expect("failed to create system resolvers");

    let mq = MultiQuery::new(name, [RecordType::A, RecordType::AAAA, RecordType::TXT])
        .expect("failed to create multi-query");
    let start_time = Instant::now();
    let lookups = resolvers.multi_lookup(mq).await;
    let total_run_time = Instant::now() - start_time;

    //println!("Multi-Lookup results: {:#?}", lookups);

    let successes = lookups.iter().filter(|x| x.result().is_response()).count();
    println!("Multi-Lookup successful results: {}/{}", successes, lookups.len());

    let failures: Vec<_> = lookups.iter().filter(|x| !x.result().is_response()).collect();
    println!("Multi-Lookup failed results: {:#?}", failures.len());

    let statistics = lookups.statistics();
    println!("Statistics: {:#?}", statistics);

    let rr_types = statistics
        .rr_type_counts
        .iter()
        .map(|x| format!("{} {}", x.1, x.0))
        .collect::<Vec<_>>()
        .as_slice()
        .join(", ");
    let num_rr = statistics.rr_type_counts.values().fold(0, |acc, count| acc + count);
    println!("Received {num_resp} responses with {num_rr} RR [{rr_types}], {num_nx} Nx, {num_to} TO, {num_err} Err in (min {min_time}, max {max_time}) ms from {num_srvs} server within {total_time} ms total runtime.",
             num_resp = statistics.responses,
             num_rr = num_rr,
             rr_types = rr_types,
             num_nx = statistics.nxdomains,
             num_to = statistics.timeouts,
             num_err = statistics.errors,
             min_time = statistics.response_time_summary.min.map(|x| x.to_string()).unwrap_or_else(|| "-".to_string()),
             max_time = statistics.response_time_summary.max.map(|x| x.to_string()).unwrap_or_else(|| "-".to_string()),
             num_srvs = statistics.responding_servers,
             total_time = total_run_time.as_millis(),
    );
}
