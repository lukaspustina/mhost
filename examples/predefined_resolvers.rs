use mhost::resolver::{predefined, ResolverGroup, UniQuery};
use mhost::RecordType;
use std::env;
use env_logger;

#[tokio::main]
async fn main() {
    env_logger::init();

    let name = env::args().nth(1).unwrap_or_else(|| "www.example.com".to_string());

    let resolver_configs = predefined::resolver_configs();

    let resolvers = ResolverGroup::from_configs(resolver_configs, Default::default(), Default::default())
        .await
        .expect("failed to create resolvers");

    let q = UniQuery::new(name, RecordType::A).expect("Failed to create multi-query");
    let lookups = resolvers.lookup(q).await;
    //println!("Multi-Lookup results: {:#?}", lookups);

    let successes = lookups.iter().filter(|x| x.result().is_response()).count();
    println!("Multi-Lookup successful results: {}/{}", successes, lookups.len());

    let failures: Vec<_> = lookups.iter().filter(|x| !x.result().is_response()).collect();
    println!("Multi-Lookup failed results: {:#?}", failures);
}
