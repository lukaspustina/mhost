use mhost::resolver::{predefined, ResolverGroup};
use mhost::{Query, RecordType};
use std::env;

#[tokio::main]
async fn main() {
    let name = env::args()
        .skip(1)
        .next()
        .unwrap_or_else(|| "www.example.com".to_string());

    let resolver_configs = predefined::resolver_configs();

    let resolvers = ResolverGroup::from_configs(resolver_configs, Default::default(), Default::default())
        .await
        .expect("failed to create resolvers");

    let q = Query::new(name, RecordType::A).expect("Failed to create multi-query");
    let lookups = resolvers.lookup(q).await;

    //println!("Multi-Lookup results: {:#?}", lookups);

    let successes = lookups.iter().filter(|x| x.result().is_ok()).count();
    println!("Multi-Lookup successful results: {}/{}", successes, lookups.len());

    let failures: Vec<_> = lookups.iter().filter(|x| !x.result().is_ok()).collect();
    println!("Multi-Lookup failed results: {:#?}", failures);
}
