// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::env;
use std::net::SocketAddr;

use mhost::nameserver::NameServerConfig;
use mhost::resolver::{MultiQuery, ResolverGroupBuilder};
use mhost::RecordType;

#[tokio::main]
async fn main() {
    let name = env::args().nth(1).unwrap_or_else(|| "www.example.com".to_string());

    let sock_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let resolvers = ResolverGroupBuilder::new()
        .nameserver(NameServerConfig::udp(sock_addr))
        .build()
        .await
        .expect("Failed to create resolver");

    let mq = MultiQuery::multi_record(name, vec![RecordType::A, RecordType::AAAA, RecordType::TXT])
        .expect("Failed to create multi-query");
    let lookups = resolvers.lookup(mq).await.expect("failed to execute lookups");

    let json = serde_json::to_string_pretty(&lookups).expect("failed to serialize lookups");
    println!("{}", &json);
}
