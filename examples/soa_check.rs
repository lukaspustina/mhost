// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::env;

use mhost::estimate::Estimate;
use mhost::nameserver::NameServerConfig;
use mhost::resolver::lookup::Uniquify;
use mhost::resolver::{MultiQuery, ResolverConfig, ResolverGroup, UniQuery};
use mhost::RecordType;

#[tokio::main]
async fn main() {
    let name = env::args().nth(1).unwrap_or_else(|| "example.com".to_string());

    let resolvers = ResolverGroup::from_system_config(Default::default())
        .await
        .expect("failed to create system resolvers");

    let q = UniQuery::new(name.clone(), RecordType::NS).expect("failed to create NS query");
    println!(
        "Sending {} requests for names of authoritative name servers.",
        resolvers.estimate(&q.clone().into())
    );
    let authoritative_name_server_names = resolvers.lookup(q).await.unwrap().ns().unique().to_owned();
    // println!("Authoritative name server names: {:#?}", &authoritative_name_server_names);

    let q =
        MultiQuery::multi_name(authoritative_name_server_names, RecordType::A).expect("failed to create NS IP query");
    println!(
        "Sending {} requests for IPv4 addresses of authoritative name servers.",
        resolvers.estimate(&q)
    );
    let authoritative_name_server_ips = resolvers.lookup(q).await.unwrap().a().unique().to_owned();
    // println!("Authoritative name server name IPs: {:#?}", &authoritative_name_server_ips);

    let authoritative_name_servers = authoritative_name_server_ips
        .into_iter()
        .map(|ip| NameServerConfig::udp((ip, 53)))
        .map(ResolverConfig::new);
    let resolvers = ResolverGroup::from_configs(authoritative_name_servers, Default::default(), Default::default())
        .await
        .expect("failed to create authoritative resolvers");

    let q = UniQuery::new(name, RecordType::SOA).expect("failed to create SOA query");
    println!(
        "Sending {} requests for SOA records of authoritative name servers.",
        resolvers.estimate(&q.clone().into())
    );
    let soas = resolvers.lookup(q).await.unwrap().soa().unique().to_owned();
    println!("SOAs -- should be exactly one: {:#?}", &soas);
}
