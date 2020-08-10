use log::info;
use std::time::Instant;

use anyhow::Result;

use crate::app::cli::{print_error_counts, print_estimates_lookups, print_opts, print_statistics, print_estimates_whois};
use crate::app::modules::lookup::config::LookupConfig;
use crate::app::resolver::{build_query, create_resolvers, load_resolver_group_opts, load_resolver_opts};
use crate::app::{output, resolver, GlobalConfig};
use crate::resolver::lookup::Uniquify;
use crate::resolver::Lookups;
use crate::services::ripe_stats::{MultiQuery, QueryType, RipeStats, RipeStatsOpts, RipeStatsResponses};
use clap::ArgMatches;
use ipnetwork::IpNetwork;
use std::convert::TryInto;
use std::net::IpAddr;
use crate::output::{CAPTION_PREFIX, styles::EMPH};

pub mod config;

pub async fn run(args: &ArgMatches<'_>, global_config: &GlobalConfig) -> Result<()> {
    info!("lookup module selected.");
    let args = args.subcommand_matches("lookup").unwrap();
    let config: LookupConfig = args.try_into()?;
    let lookups = lookups(&global_config, &config).await?;

    if config.whois {
        whois(global_config, &config, &lookups).await?;
    }

    Ok(())
}

pub async fn lookups(global_config: &GlobalConfig, config: &LookupConfig) -> Result<Lookups> {
    let query = build_query(&config.domain_name, &config.record_types)?;

    let resolver_group_opts = load_resolver_group_opts(&global_config)?;
    let resolver_opts = load_resolver_opts(&global_config)?;

    if !global_config.quiet {
        print_opts(&resolver_group_opts, &resolver_opts);
        println!("{}", EMPH.paint(format!("{} Running DNS lookups.", CAPTION_PREFIX)));
    }

    let resolvers = create_resolvers(global_config, resolver_group_opts, resolver_opts).await?;

    if !global_config.quiet {
        print_estimates_lookups(&resolvers, &query);
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

    Ok(lookups)
}

pub async fn whois(
    global_config: &GlobalConfig,
    _config: &LookupConfig,
    lookups: &Lookups,
) -> Result<RipeStatsResponses> {
    let ip_addresses = ips_from_lookups(lookups);
    let query_types = vec![QueryType::NetworkInfo, QueryType::GeoLocation, QueryType::Whois];
    let query = MultiQuery::from_iter(ip_addresses, query_types);

    let opts = RipeStatsOpts::new(8, global_config.abort_on_error);
    let whois_client = RipeStats::new(opts);

    if !global_config.quiet {
        println!("{}", EMPH.paint(format!("{} Running WHOIS queries.", CAPTION_PREFIX)));
        print_estimates_whois(&query);
    }

    info!("Running Whois queries");
    let start_time = Instant::now();
    let whois = whois_client.query(query).await?;
    let total_run_time = Instant::now() - start_time;
    info!("Finished queries.");

    if !global_config.quiet {
        print_statistics(&whois, total_run_time);
    }

    output::output(global_config, &whois)?;

    Ok(whois)
}

fn ips_from_lookups(lookups: &Lookups) -> impl Iterator<Item = IpNetwork> {
    lookups
        .a()
        .unique()
        .to_owned()
        .into_iter()
        .map(|x| IpAddr::V4(x))
        .chain(lookups.aaaa().unique().to_owned().into_iter().map(|x| IpAddr::V6(x)))
        .map(IpNetwork::from)
}
