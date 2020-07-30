use std::time::Instant;

use anyhow::Result;

use crate::app::*;
use crate::resolver::Lookups;

pub async fn run(config: &Config) -> Result<()> {
    if config.list_predefined {
        list_predefined_nameservers();
        return Ok(());
    }

    let query = build_query(&config.domain_name, &config.record_types)?;

    let resolver_group_opts = load_resolver_group_opts(&config)?;
    let resolver_opts = load_resolver_opts(&config)?;

    if !config.quiet {
        print_opts(&resolver_group_opts, &resolver_opts);
    }

    let resolvers = create_resolvers(config, resolver_group_opts, resolver_opts).await?;

    if !config.quiet {
        print_estimates(&resolvers, &query);
    }

    let start_time = Instant::now();
    let lookups: Lookups = lookup(config.randomized_lookup, query, resolvers).await;
    let total_run_time = Instant::now() - start_time;

    if !config.quiet {
        print_statistics(&lookups, total_run_time);
    }

    output(&lookups)
}
