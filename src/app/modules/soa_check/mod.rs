use crate::app::cli::{print_estimates_lookups, print_opts, print_statistics};
use crate::app::modules::soa_check::config::SoaCheckConfig;
use crate::app::resolver::{create_resolvers, load_resolver_group_opts, load_resolver_opts};
use crate::app::{output, GlobalConfig};
use crate::diff::SetDiffer;
use crate::nameserver::NameServerConfig;
use crate::output::styles::{self, ATTENTION_PREFIX, CAPTION_PREFIX, ERROR_PREFIX, OK_PREFIX};
use crate::resolver::lookup::Uniquify;
use crate::resolver::{MultiQuery, ResolverConfig, ResolverGroup};
use crate::RecordType;
use anyhow::Result;
use clap::ArgMatches;
use indexmap::set::IndexSet;
use log::info;
use std::convert::TryInto;
use std::net::IpAddr;
use std::time::Instant;

pub mod config;

pub async fn run(args: &ArgMatches<'_>, global_config: &GlobalConfig) -> Result<()> {
    info!("soa-check module selected.");
    let args = args.subcommand_matches("soa-check").unwrap();
    let config: SoaCheckConfig = args.try_into()?;
    soa_check(&global_config, &config).await
}

pub async fn soa_check(global_config: &GlobalConfig, config: &SoaCheckConfig) -> Result<()> {
    // NS
    let query = MultiQuery::single(config.domain_name.as_str(), RecordType::NS)?;

    let resolver_group_opts = load_resolver_group_opts(&global_config)?;
    let resolver_opts = load_resolver_opts(&global_config)?;

    if !global_config.quiet {
        print_opts(&resolver_group_opts, &resolver_opts);
    }

    let resolvers = create_resolvers(global_config, resolver_group_opts.clone(), resolver_opts.clone()).await?;

    if !global_config.quiet && config.partial_results {
        println!(
            "{}",
            styles::EMPH.paint(format!("{} Running DNS lookups of name servers.", &*CAPTION_PREFIX))
        );
        print_estimates_lookups(&resolvers, &query);
    }

    info!("Running lookups for authoritative name servers");
    let start_time = Instant::now();
    let lookups = resolvers.lookup(query).await?;
    let total_run_time = Instant::now() - start_time;
    info!("Finished Lookups.");

    if !global_config.quiet && config.partial_results {
        print_statistics(&lookups, total_run_time);
    }
    if config.partial_results {
        output::output(global_config, &lookups)?;
    }
    if !lookups.has_records() {
        println!(
            "{} No authoritative nameservers found. Aborting.",
            styles::ATTENTION.paint(&*ERROR_PREFIX)
        );
        return Ok(());
    }

    let authoritative_name_server_names = lookups.ns().unique().to_owned();

    // A, AAAA -> IP

    let query = MultiQuery::new(authoritative_name_server_names, vec![RecordType::A, RecordType::AAAA])?;
    if !global_config.quiet && config.partial_results {
        println!(
            "{}",
            styles::EMPH.paint(format!(
                "{} Running DNS lookups of IPv4 and IPv6 addresses of name servers.",
                &*CAPTION_PREFIX
            ))
        );
        print_estimates_lookups(&resolvers, &query);
    }

    info!("Running lookups for IP addresses of authoritative name servers");
    let start_time = Instant::now();
    let lookups = resolvers.lookup(query).await?;
    let total_run_time = Instant::now() - start_time;
    info!("Finished Lookups.");

    if !global_config.quiet && config.partial_results {
        print_statistics(&lookups, total_run_time);
    }
    if config.partial_results {
        output::output(global_config, &lookups)?;
    }
    if !lookups.has_records() {
        println!(
            "{} No IP addresses for authoritative nameservers found. Aborting.",
            styles::ATTENTION.paint(&*ERROR_PREFIX)
        );
        return Ok(());
    }

    let authoritative_name_server_ips = lookups
        .a()
        .unique()
        .to_owned()
        .into_iter()
        .map(IpAddr::from)
        .chain(lookups.aaaa().unique().to_owned().into_iter().map(IpAddr::from));

    // SOA

    let authoritative_name_servers = authoritative_name_server_ips
        .map(|ip| NameServerConfig::udp((ip, 53)))
        .map(ResolverConfig::new);
    let resolvers = ResolverGroup::from_configs(authoritative_name_servers, resolver_opts, resolver_group_opts).await?;

    let query = MultiQuery::single(config.domain_name.as_str(), RecordType::SOA)?;
    if !global_config.quiet {
        println!(
            "{}",
            styles::EMPH.paint(format!("{} Running DNS lookups for SOA records.", &*CAPTION_PREFIX))
        );
        print_estimates_lookups(&resolvers, &query);
    }

    info!("Running lookups for SOA records of authoritative name servers");
    let start_time = Instant::now();
    let lookups = resolvers.lookup(query).await?;
    let total_run_time = Instant::now() - start_time;
    info!("Finished Lookups.");

    if !global_config.quiet {
        print_statistics(&lookups, total_run_time);
    }
    output::output(global_config, &lookups)?;
    if !lookups.has_records() {
        println!(
            "{} No SOA records from authoritative nameservers found. Aborting.",
            styles::ATTENTION.paint(&*ERROR_PREFIX)
        );
        return Ok(());
    }

    let soas: IndexSet<_> = lookups.soa().unique().to_owned().into_iter().collect();
    let diffs = soas.differences();

    if let Some(diffs) = diffs {
        println!(
            "{} Found deviations in SOA records: ",
            styles::ATTENTION.paint(&*ATTENTION_PREFIX),
        );
        println!("{:?}", diffs);
    } else {
        println!("{} All SOA records in sync.", styles::OK.paint(&*OK_PREFIX),);
    }

    Ok(())
}
