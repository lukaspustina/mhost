// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::env;
use std::net::{Ipv4Addr, SocketAddr};

use mhost::nameserver::NameServerConfig;
use mhost::resolver::{MultiQuery, Resolver, ResolverGroup};
use mhost::RecordType;

#[tokio::main]
async fn main() {
    let name = env::args().nth(1).unwrap_or_else(|| "www.example.com".to_string());

    let sock_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let config = NameServerConfig::udp(sock_addr).into();
    let resolver = Resolver::new(config, Default::default())
        .await
        .expect("Failed to create resolver");

    let mut resolvers = ResolverGroup::new([resolver], Default::default());

    let config = NameServerConfig::udp((Ipv4Addr::new(8, 8, 8, 8), 53)).into();
    let resolvers_2 = ResolverGroup::from_configs(vec![config], Default::default(), Default::default())
        .await
        .expect("Failed to create 2. resolver group");

    resolvers.merge(resolvers_2);

    let mq = MultiQuery::multi_record(name, vec![RecordType::A, RecordType::AAAA, RecordType::TXT])
        .expect("Failed to create multi-query");
    let lookups = resolvers.lookup(mq).await.expect("failed to execute lookups");

    //println!("Multi-Lookup results: {:#?}", multi_lookup);

    let successes = lookups.iter().filter(|x| x.result().is_response()).count();
    println!("Multi-Lookup successful results: {}/{}", successes, lookups.len());

    let failures: Vec<_> = lookups.iter().filter(|x| !x.result().is_response()).collect();
    println!("Multi-Lookup failed results: {:#?}", failures);
}
