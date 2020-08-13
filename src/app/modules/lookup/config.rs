use std::convert::TryFrom;
use std::str::FromStr;

use anyhow::{Context, Result};
use clap::{App, Arg, ArgMatches, SubCommand};

use crate::app::global_config::SUPPORTED_RECORD_TYPES;
use crate::RecordType;

pub fn subcommand() -> App<'static, 'static> {
    SubCommand::with_name("lookup")
        .about("Looks up a name, IP address or CIDR block")
        .arg(Arg::with_name("domain name")
            .required_unless("list-predefined")
            .index(1)
            .value_name("NAME | IP ADDR | CIDR BLOCK")
            .next_line_help(false)
            .help("domain name, IP address, or CIDR block to lookup")
            .long_help(
                "* DOMAIN NAME may be any valid DNS name, e.g., lukas.pustina.de
* IP ADDR may be any valid IPv4 or IPv4 address, e.g., 192.168.0.1
* CIDR BLOCK may be any valid IPv4 or IPv6 subnet in CIDR notation, e.g., 192.168.0.1/24
  all valid IP addresses of a CIDR block will be queried for a reverse lookup")
        )
        .arg(Arg::with_name("record types")
            .short("t")
            .long("record-type")
            .value_name("RECORD TYPE")
            .takes_value(true)
            .multiple(true)
            .use_delimiter(true)
            .require_delimiter(true)
            .default_value("A,AAAA,MX")
            .possible_values(SUPPORTED_RECORD_TYPES)
            .help("Sets record type to lookup, will be ignored in case of IP address lookup")
        )
        .arg(Arg::with_name("all-record-types")
            .long("all")
            .alias("xmas")
            .help("Enables lookups for all record types")
        )
        .arg(Arg::with_name("randomized-lookup")
            .short("R")
            .long("randomized-lookup")
            .help("Switches into randomize lookup mode: every query will be send just one randomly chosen nameserver. This can be used to distribute queries among the available nameservers.")
        )
        .arg(Arg::with_name("whois")
            .short("w")
            .long("whois")
            .help("Retrieves Whois information about A, AAAA, and PTR records.")
        )
}

pub struct LookupConfig {
    pub domain_name: String,
    pub record_types: Vec<RecordType>,
    pub randomized_lookup: bool,
    pub whois: bool,
}

impl TryFrom<&ArgMatches<'_>> for LookupConfig {
    type Error = anyhow::Error;

    fn try_from(args: &ArgMatches) -> std::result::Result<Self, Self::Error> {
        let config = LookupConfig {
            domain_name: args
                .value_of("domain name")
                .context("No domain name to lookup specified")?
                .to_string(),
            record_types: record_types(&args)?,
            randomized_lookup: args.is_present("randomized-lookup"),
            whois: args.is_present("whois"),
        };

        Ok(config)
    }
}

fn record_types(args: &ArgMatches<'_>) -> Result<Vec<RecordType>> {
    if args.is_present("all-record-types") {
        Ok(SUPPORTED_RECORD_TYPES
            .iter()
            .map(|x| RecordType::from_str(x).unwrap())
            .collect())
    } else {
        let args = args
            .values_of("record types")
            .context("No record types for name lookup specified")?;
        parse_record_types(args)
    }
}

fn parse_record_types<'a, I: Iterator<Item = &'a str>>(record_types: I) -> Result<Vec<RecordType>> {
    let record_types: Vec<_> = record_types
        .map(str::to_uppercase)
        .map(|x| RecordType::from_str(&x))
        .collect();
    let record_types: std::result::Result<Vec<_>, _> = record_types.into_iter().collect();
    record_types.context("Failed to parse record type")
}
