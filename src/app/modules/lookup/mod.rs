use std::convert::TryInto;
use std::net::IpAddr;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::ArgMatches;
use ipnetwork::IpNetwork;
use log::info;

use crate::app::cli::{
    print_error_counts, print_estimates_lookups, print_estimates_whois, print_opts, print_statistics, ExitStatus,
};
use crate::app::modules::lookup::config::LookupConfig;
use crate::app::resolver::AppResolver;
use crate::app::{output, GlobalConfig};
use crate::output::styles::{self, CAPTION_PREFIX};
use crate::resolver::lookup::Uniquify;
use crate::resolver::{Lookups, MultiQuery};
use crate::resources::NameToIpAddr;
use crate::services::whois::{self, QueryType, WhoisClient, WhoisClientOpts, WhoisResponses};
use crate::RecordType;
use std::collections::HashSet;
use std::str::FromStr;
use tokio::time::Duration;

pub mod config;

pub async fn run(args: &ArgMatches<'_>, global_config: &GlobalConfig) -> Result<ExitStatus> {
    info!("lookup module selected.");
    let args = args.subcommand_matches("lookup").unwrap();
    let config: LookupConfig = args.try_into()?;
    let lookups = lookups(&global_config, &config).await?;

    if config.whois {
        whois(global_config, &config, &lookups).await?;
    }

    Ok(ExitStatus::Ok)
}

pub async fn lookups(global_config: &GlobalConfig, config: &LookupConfig) -> Result<Lookups> {
    let query = build_query(&config.domain_name, &config.record_types)?;
    let app_resolver = AppResolver::create_resolvers(global_config)
        .await?
        .with_single_server_lookup(config.single_server_lookup);

    if !global_config.quiet {
        print_opts(app_resolver.resolver_group_opts(), &app_resolver.resolver_opts());
        println!(
            "{}",
            styles::EMPH.paint(format!("{} Running DNS lookups.", &*CAPTION_PREFIX))
        );
        print_estimates_lookups(app_resolver.resolvers(), &query);
    }

    info!("Running lookups");
    let start_time = Instant::now();
    let lookups: Lookups = app_resolver.lookup(query).await?;
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

fn build_query(domain_name: &str, record_types: &[RecordType]) -> Result<MultiQuery> {
    if let Ok(ip_network) = IpNetwork::from_str(domain_name) {
        ptr_query(ip_network)
    } else {
        name_query(domain_name, record_types)
    }
}

fn ptr_query(ip_network: IpNetwork) -> Result<MultiQuery> {
    let q = MultiQuery::multi_name(ip_network.iter(), RecordType::PTR).context("Failed to create query")?;
    info!("Prepared query for reverse lookups.");
    Ok(q)
}

fn name_query(name: &str, record_types: &[RecordType]) -> Result<MultiQuery> {
    let record_types_len = record_types.len();
    let q = MultiQuery::multi_record(name, record_types.to_vec()).context("Failed to build query")?;
    info!("Prepared query for name lookup for {} record types.", record_types_len);
    Ok(q)
}

pub async fn whois(global_config: &GlobalConfig, _config: &LookupConfig, lookups: &Lookups) -> Result<WhoisResponses> {
    let ip_addresses = ips_from_lookups(lookups)?;
    let query_types = vec![QueryType::NetworkInfo, QueryType::GeoLocation, QueryType::Whois];
    let query = whois::MultiQuery::from_iter(ip_addresses, query_types);

    let opts = WhoisClientOpts::with_cache(8, global_config.abort_on_error, 1024, Duration::from_secs(60));
    let whois_client = WhoisClient::new(opts);

    if !global_config.quiet {
        println!(
            "{}",
            styles::EMPH.paint(format!("{} Running WHOIS queries.", &*CAPTION_PREFIX))
        );
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

fn ips_from_lookups(lookups: &Lookups) -> Result<impl Iterator<Item = IpNetwork>> {
    let ptrs: Vec<_> = lookups
        .iter()
        .filter(|x| x.query().record_type == RecordType::PTR)
        .map(|x| x.query().name())
        .map(|x| x.to_ip_addr())
        .collect();
    let ptrs: crate::Result<Vec<_>> = ptrs.into_iter().collect();
    let ptrs = ptrs?;
    let ptrs: HashSet<IpAddr> = ptrs.into_iter().collect();
    let ips = lookups
        .a()
        .unique()
        .to_owned()
        .into_iter()
        .map(IpAddr::V4)
        .chain(lookups.aaaa().unique().to_owned().into_iter().map(IpAddr::V6))
        .map(IpNetwork::from);
    Ok(ptrs.into_iter().map(IpNetwork::from).chain(ips))
}
