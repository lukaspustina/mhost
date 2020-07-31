use mhost::nameserver::NameServerConfig;
use mhost::resolver::{MultiQuery, Resolver, ResolverConfig, UniQuery};
use mhost::RecordType;
use std::env;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let name = env::args().nth(1).unwrap_or_else(|| "www.example.com".to_string());

    let sock_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let name_server_config = NameServerConfig::udp(sock_addr);
    let config = ResolverConfig::new(name_server_config);

    let resolver = Resolver::new(config, Default::default())
        .await
        .expect("Failed to create resolver");

    let query = UniQuery::new(name, RecordType::A).expect("Failed to create query");
    let one_lookup = resolver.lookup(query).await.expect("failed to execute lookups");
    println!("Lookup result: #{} {:?}", one_lookup.len(), &one_lookup);

    let mq = MultiQuery::multi_record(
        "www.example.com",
        vec![RecordType::A, RecordType::AAAA, RecordType::TXT],
    )
    .expect("Failed to create multi-query");
    let lookups = resolver.lookup(mq).await.expect("failed to execute lookups");

    //println!("Multi-Lookup results: {:#?}", multi_lookup);

    let successes = lookups.iter().filter(|x| x.result().is_response()).count();
    println!("Multi-Lookup successful results: {}/{}", successes, lookups.len());

    let failures: Vec<_> = lookups.iter().filter(|x| !x.result().is_response()).collect();
    println!("Multi-Lookup failed results: {:#?}", failures);
}
