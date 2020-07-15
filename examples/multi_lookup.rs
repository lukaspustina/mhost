use mhost::nameserver::NameServerConfig;
use mhost::resolver::{Resolver, ResolverConfig};
use mhost::{MultiQuery, Query, RecordType};
use std::env;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let name = env::args()
        .skip(1)
        .next()
        .unwrap_or_else(|| "www.example.com".to_string());

    let sock_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let name_server_config = NameServerConfig::udp(sock_addr);
    let config = ResolverConfig::new(name_server_config);

    let resolver = Resolver::new(config, Default::default())
        .await
        .expect("Failed to create resolver");

    let query = Query::new(name, RecordType::A).expect("Failed to create query");
    let _one_lookup = resolver.lookup(query).await;
    println!("Lookup result: 1");

    let mq = MultiQuery::new("www.example.com", [RecordType::A, RecordType::AAAA, RecordType::TXT])
        .expect("Failed to create multi-query");
    let lookups = resolver.multi_lookup(mq).await;

    //println!("Multi-Lookup results: {:#?}", multi_lookup);

    let successes = lookups.iter().filter(|x| x.result().is_ok()).count();
    println!("Multi-Lookup successful results: {}/{}", successes, lookups.len());

    let failures: Vec<_> = lookups.iter().filter(|x| !x.result().is_ok()).collect();
    println!("Multi-Lookup failed results: {:#?}", failures);
}
