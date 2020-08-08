use std::convert::TryFrom;

use anyhow::Context;
use clap::{App, Arg, ArgMatches, SubCommand};

pub fn subcommand() -> App<'static, 'static> {
    SubCommand::with_name("soa-check")
        .about("Checks SOA records of authoritative name servers for deviations")
        .arg(
            Arg::with_name("domain name")
                .index(1)
                .value_name("NAME")
                .next_line_help(false)
                .help("domain name to check")
                .long_help("* DOMAIN NAME may be any valid DNS name, e.g., lukas.pustina.de"),
        )
        .arg(
            Arg::with_name("partial-results")
                .short("p")
                .long("show-partial-results")
                .help("Shows results after each lookup step"),
        )
}

pub struct SoaCheckConfig {
    pub domain_name: String,
    pub partial_results: bool,
}

impl TryFrom<&ArgMatches<'_>> for SoaCheckConfig {
    type Error = anyhow::Error;

    fn try_from(args: &ArgMatches) -> std::result::Result<Self, Self::Error> {
        let config = SoaCheckConfig {
            domain_name: args
                .value_of("domain name")
                .context("No domain name to lookup specified")?
                .to_string(),
            partial_results: args.is_present("partial-results"),
        };

        Ok(config)
    }
}
