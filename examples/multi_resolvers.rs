use mhost::nameserver::NameServerConfig;
use mhost::resolver::{Resolver, ResolverConfig, ResolverOpts, ResolverGroup};
use mhost::{MultiQuery, RecordType};
use std::net::{IpAddr, Ipv4Addr};

#[tokio::main]
async fn main() {
    let ip_addr: IpAddr = Ipv4Addr::new(8, 8, 8, 8).into();
    let name_server_config = NameServerConfig::udp(ip_addr, 53);
    let config = ResolverConfig::new(name_server_config);
    let opts = ResolverOpts::default();
    let resolver = Resolver::new(config, opts).await.expect("Failed to create resolver");

    let mut resolvers = ResolverGroup::new([resolver], Default::default());

    let ip_addr: IpAddr = Ipv4Addr::new(8, 8, 8, 8).into();
    let name_server_config = NameServerConfig::udp(ip_addr, 53);
    let config = ResolverConfig::new(name_server_config);
    let opts = ResolverOpts::default();

    let resolvers_2 = ResolverGroup::from_configs(vec![config], opts, Default::default()).await
        .expect("Failed to create 2. resolver group");

    resolvers.merge(resolvers_2);
    let mq = MultiQuery::new("www.example.com", [RecordType::A, RecordType::AAAA, RecordType::TXT])
        .expect("Failed to create multi-query");
    let multi_lookup = resolvers.multi_lookup(mq).await;
    println!("Multi-Lookup results: {:#?}", multi_lookup.len());
}
