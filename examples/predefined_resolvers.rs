use mhost::nameserver;
use mhost::resolver::{ResolverConfig, ResolverGroup};
use mhost::{Query, RecordType};
use std::env;

#[tokio::main]
async fn main() {
    let name = env::args()
        .skip(1)
        .next()
        .unwrap_or_else(|| "www.example.com".to_string());

    let resolver_configs: Vec<_> = vec![
        nameserver::predefined::cloudflare::udp(),
        nameserver::predefined::cloudflare::tcp(),
        nameserver::predefined::cloudflare::https(),
        nameserver::predefined::cloudflare::tls(),
        nameserver::predefined::google::udp(),
        nameserver::predefined::google::tcp(),
        nameserver::predefined::opennic::udp(),
        nameserver::predefined::opennic::tcp(),
        nameserver::predefined::quad9::udp(),
        nameserver::predefined::quad9::tcp(),
    ]
    .into_iter()
    .map(|x| ResolverConfig::new(x))
    .collect();

    let resolvers = ResolverGroup::from_configs(resolver_configs, Default::default(), Default::default())
        .await
        .expect("failed to create resolvers");

    let q = Query::new(name, RecordType::A).expect("Failed to create multi-query");
    let lookups = resolvers.lookup(q).await;
    //println!("Multi-Lookup results: {:#?}", lookups.len());
    println!("Multi-Lookup results: {:#?}", lookups);
}
