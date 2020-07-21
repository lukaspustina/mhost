use std::net::SocketAddr;
use std::{env, io};

use mhost::nameserver::NameServerConfig;
use mhost::output::{Output, OutputConfig, OutputFormat};
use mhost::resolver::{MultiQuery, Resolver, ResolverConfig};
use mhost::RecordType;

#[tokio::main]
async fn main() {
    let name = env::args().nth(1).unwrap_or_else(|| "www.example.com".to_string());

    let sock_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let name_server_config = NameServerConfig::udp(sock_addr);
    let config = ResolverConfig::new(name_server_config);

    let resolver = Resolver::new(config, Default::default())
        .await
        .expect("Failed to create resolver");

    let mq = MultiQuery::multi_record(name, vec![RecordType::A, RecordType::AAAA, RecordType::TXT])
        .expect("Failed to create multi-query");
    let lookups = resolver.lookup(mq).await;

    let stdout = io::stdout();
    let mut handle = stdout.lock();

    let config = OutputConfig::json();
    let output = Output::new(config);
    output
        .output(&mut handle, &lookups)
        .expect("failed to serialize to stdout");
}
