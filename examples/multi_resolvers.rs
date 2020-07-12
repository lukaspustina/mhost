use mhost::nameserver::NameServerConfig;
use mhost::resolver::{Resolver, ResolverConfig, ResolverGroup, ResolverOpts};
use mhost::{MultiQuery, RecordType};
use std::env;
use std::net::{Ipv4Addr, SocketAddr};

#[tokio::main]
async fn main() {
    let name = env::args()
        .skip(1)
        .next()
        .unwrap_or_else(|| "www.example.com".to_string());

    let sock_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let name_server_config = NameServerConfig::udp(sock_addr);
    let config = ResolverConfig::new(name_server_config);
    let opts = ResolverOpts::default();
    let resolver = Resolver::new(config, opts).await.expect("Failed to create resolver");

    let mut resolvers = ResolverGroup::new([resolver], Default::default());

    let name_server_config = NameServerConfig::udp((Ipv4Addr::new(8, 8, 8, 8), 53));
    let config = ResolverConfig::new(name_server_config);

    let resolvers_2 = ResolverGroup::from_configs(vec![config], Default::default(), Default::default())
        .await
        .expect("Failed to create 2. resolver group");

    resolvers.merge(resolvers_2);
    let mq = MultiQuery::new(name, [RecordType::A, RecordType::AAAA, RecordType::TXT])
        .expect("Failed to create multi-query");
    let multi_lookup = resolvers.multi_lookup(mq).await;
    //println!("Multi-Lookup results: {:#?}", multi_lookup.len());
    println!("Multi-Lookup results: {:#?}", multi_lookup);
}
