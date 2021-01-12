// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::env;
use std::time::Instant;

use mhost::resolver::{predefined, Mode, MultiQuery, ResolverGroup, ResolverGroupOpts};
use mhost::statistics::Statistics;
use mhost::RecordType;

#[tokio::main]
async fn main() {
    let name = env::args().nth(1).unwrap_or_else(|| "www.example.com".to_string());

    let resolver_configs = predefined::resolver_configs();
    let resolvers_opts = ResolverGroupOpts {
        mode: Mode::Uni,
        ..Default::default()
    };
    let resolvers = ResolverGroup::from_configs(resolver_configs, Default::default(), resolvers_opts)
        .await
        .expect("failed to create resolvers");

    let mq = MultiQuery::multi_record(
        name,
        vec![
            RecordType::A,
            RecordType::AAAA,
            RecordType::ANAME,
            RecordType::CNAME,
            RecordType::MX,
            RecordType::NULL,
            RecordType::NS,
            RecordType::PTR,
            RecordType::SOA,
            RecordType::SRV,
            RecordType::TXT,
        ],
    )
    .expect("Failed to create multi-query");
    let start_time = Instant::now();
    let lookups = resolvers.lookup(mq).await.expect("failed to execute lookups");
    let total_run_time = Instant::now() - start_time;

    let statistics = lookups.statistics();
    println!(
        "Received {} within {} ms of total run time.",
        statistics,
        total_run_time.as_millis()
    );
    println!("Results:\n{:#?}", &lookups);
}
