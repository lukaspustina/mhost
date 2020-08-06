use log::info;
use std::time::Instant;

use anyhow::Result;

use crate::app::*;
use crate::resolver::Lookups;
use crate::app::config::LookupConfig;

pub async fn run(global_config: &GlobalConfig, config: &LookupConfig) -> Result<()> {
    let query = build_query(&config.domain_name, &config.record_types)?;

    let resolver_group_opts = load_resolver_group_opts(&global_config)?;
    let resolver_opts = load_resolver_opts(&global_config)?;

    if !global_config.quiet {
        print_opts(&resolver_group_opts, &resolver_opts);
    }

    let resolvers = create_resolvers(global_config, resolver_group_opts, resolver_opts).await?;

    if !global_config.quiet {
        print_estimates(&resolvers, &query);
    }

    info!("Running lookups");
    let start_time = Instant::now();
    let lookups: Lookups = lookup(config.randomized_lookup, query, resolvers).await?;
    let total_run_time = Instant::now() - start_time;
    info!("Finished Lookups.");

    if !global_config.quiet {
        print_statistics(&lookups, total_run_time);
    }

    output(global_config, &lookups)?;

    if !global_config.quiet && global_config.show_errors {
        print_error_counts(&lookups);
    }

    Ok(())
}
