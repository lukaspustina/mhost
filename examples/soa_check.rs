use std::env;

use mhost::nameserver::NameServerConfig;
use mhost::resolver::lookup::Uniquify;
use mhost::resolver::{MultiQuery, ResolverConfig, ResolverGroup, UniQuery};
use mhost::RecordType;

#[tokio::main]
async fn main() {
    let name = env::args().nth(1).unwrap_or_else(|| "www.example.com".to_string());

    let resolvers = ResolverGroup::from_system_config(Default::default())
        .await
        .expect("failed to create system resolvers");

    let q = UniQuery::new(name.clone(), RecordType::NS).expect("failed to create NS query");
    let authoritative_name_server_names = resolvers.lookup(q).await.ns().unique();
    // println!("Authoritative name server names: {:#?}", &authoritative_name_server_names);

    let q =
        MultiQuery::multi_name(authoritative_name_server_names, RecordType::A).expect("failed to create NS IP query");
    let authoritative_name_server_ips = resolvers.lookup(q).await.a().unique();
    // println!("Authoritative name server name IPs: {:#?}", &authoritative_name_server_ips);

    let authoritative_name_servers = authoritative_name_server_ips
        .into_iter()
        .map(|ip| NameServerConfig::udp((ip, 53)))
        .map(ResolverConfig::new);
    let resolvers = ResolverGroup::from_configs(authoritative_name_servers, Default::default(), Default::default())
        .await
        .expect("failed to create authoritative resolvers");

    let q = UniQuery::new(name, RecordType::SOA).expect("failed to create SOA query");
    let soas = resolvers.lookup(q).await.soa().unique();
    println!("SOAs -- should be exactly one: {:#?}", &soas);
}
