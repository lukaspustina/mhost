// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use mhost::resolver::{predefined, ResolverGroup, UniQuery};
use mhost::RecordType;
use std::env;

#[tokio::main]
async fn main() {
    let name = env::args().nth(1).unwrap_or_else(|| "www.example.com".to_string());

    let resolver_configs = predefined::resolver_configs();

    let resolvers = ResolverGroup::from_configs(resolver_configs, Default::default(), Default::default())
        .await
        .expect("failed to create resolvers");

    let q = UniQuery::new(name, RecordType::A).expect("Failed to create multi-query");
    let lookups = resolvers.lookup(q).await.expect("failed to execute lookups");
    //println!("Multi-Lookup results: {:#?}", lookups);

    let successes = lookups.iter().filter(|x| x.result().is_response()).count();
    println!("Multi-Lookup successful results: {}/{}", successes, lookups.len());

    let failures: Vec<_> = lookups.iter().filter(|x| !x.result().is_response()).collect();
    println!("Multi-Lookup failed results: {:#?}", failures);
}
