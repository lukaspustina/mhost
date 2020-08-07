use log::info;
use std::time::Instant;

use anyhow::Result;

use crate::app::cli::{print_error_counts, print_estimates, print_opts, print_statistics};
use crate::app::modules::lookup::config::LookupConfig;
use crate::app::resolver::{build_query, create_resolvers, load_resolver_group_opts, load_resolver_opts};
use crate::app::{output, resolver, GlobalConfig};
use crate::resolver::Lookups;
use clap::ArgMatches;
use std::convert::TryInto;

pub mod config;

pub async fn run(args: &ArgMatches<'_>, global_config: &GlobalConfig) -> Result<()> {
    info!("lookup module selected.");
    let args = args.subcommand_matches("lookup").unwrap();
    let config: LookupConfig = args.try_into()?;
    lookups(&global_config, &config).await
}

pub async fn lookups(global_config: &GlobalConfig, config: &LookupConfig) -> Result<()> {
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
    let lookups: Lookups = resolver::lookup(config.randomized_lookup, query, resolvers).await?;
    let total_run_time = Instant::now() - start_time;
    info!("Finished Lookups.");

    if !global_config.quiet {
        print_statistics(&lookups, total_run_time);
    }

    output::output(global_config, &lookups)?;

    if !global_config.quiet && global_config.show_errors {
        print_error_counts(&lookups);
    }

    Ok(())
}
