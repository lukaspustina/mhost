use mhost::resolver::{MultiQuery, ResolverGroup};
use mhost::{IpNetwork, RecordType};
use std::env;
use std::str::FromStr;

#[tokio::main]
async fn main() {
    let cidr = env::args().nth(1).unwrap_or_else(|| "93.184.216.34".to_string());
    let ips = IpNetwork::from_str(&cidr).expect("failed to parse cidr ");

    let resolvers = ResolverGroup::from_system_config(Default::default())
        .await
        .expect("failed to create system resolvers");

    let mq = MultiQuery::multi_name(ips.iter(), RecordType::PTR).expect("Failed to create query");

    let lookups = resolvers.lookup(mq).await.expect("failed to execute lookups");
    // println!("Lookup results: {:#?}", lookup);

    for l in lookups {
        if let Some(response) = l.result().response() {
            let names = l.ptr();
            if !names.is_empty() {
                let names = names
                    .into_iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                println!("{}: {} [{:?}]", l.query().name(), names, response.response_time());
            }
        }
    }
}
