use mhost::resolver::ResolverGroup;
use mhost::{MultiQuery, RecordType};
use std::env;

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
    let multi_lookup = resolvers.multi_lookup(mq).await;

    //println!("Multi-Lookup results: {:#?}", multi_lookup);

    let successes = multi_lookup.iter().filter(|x| x.result().is_ok()).count();
    println!("Multi-Lookup successful results: {}/{}", successes, lookups.len());

    let failures: Vec<_> = multi_lookup.iter().filter(|x| !x.result().is_ok()).collect();
    println!("Multi-Lookup failed results: {:#?}", failures);
}
