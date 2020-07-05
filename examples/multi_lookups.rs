use mhost::nameserver::NameServerConfig;
use mhost::resolver::{Resolver, ResolverConfig, ResolverOpts};
use mhost::RecordType;
use std::net::{IpAddr, Ipv4Addr};

#[tokio::main]
async fn main() {
    let ip_addr: IpAddr = Ipv4Addr::new(8, 8, 8, 8).into();
    let name_server_config = NameServerConfig::udp(ip_addr, 53);
    let config = ResolverConfig::new(name_server_config);

    let opts = ResolverOpts::default();

    let resolver = Resolver::new(config, opts).await.expect("Failed to create resolver");

    let _one_lookup = resolver
        .lookup("www.example.com", RecordType::A)
        .await
        .expect("Failed to execute lookup");
    println!("Lookup: 1");

    let multi_lookup = resolver
        .multi_lookups("www.example.com", [RecordType::A, RecordType::AAAA, RecordType::TXT])
        .await
        .expect("Failed to execute multi_lookup");
    println!("Lookups: {:#?}", multi_lookup.len());
}
