use std::convert::TryFrom;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::ArgMatches;

use crate::RecordType;
use crate::resolver::ResolverOpts;

pub static SUPPORTED_RECORD_TYPES: &[&str] = &[
    "A", "AAAA", "ANAME", "CNAME", "MX", "NULL", "NS", "PTR", "SOA", "SRV", "TXT",
];

pub struct Config {
    pub domain_name: String,
    pub list_predefined: bool,
    pub record_types: Vec<RecordType>,
    pub max_concurrent_servers: usize,
    pub ignore_system_resolv_opt: bool,
    pub attempts: usize,
    pub max_concurrent_requests: usize,
    pub timeout: Duration,
    pub expects_multiple_responses: bool,
    pub abort_on_error: bool,
    pub abort_on_timeout: bool,
    pub resolv_conf_path: String,
    pub quiet: bool,
    pub ignore_system_nameservers: bool,
    pub nameservers: Option<Vec<String>>,
    pub predefined: bool,
    pub predefined_filter: Option<Vec<String>>,
    pub nameserver_file_path: Option<String>,
    pub randomized_lookup: bool,
    pub system_nameservers: Option<Vec<String>>,
}

impl TryFrom<ArgMatches<'_>> for Config {
    type Error = anyhow::Error;

    fn try_from(args: ArgMatches) -> std::result::Result<Self, Self::Error> {
        let config = Config {
            domain_name: args
                .value_of("domain name")
                .context("No domain name to lookup specified")?
                .to_string(),
            list_predefined: args.is_present("list-predefined"),
            record_types: record_types(&args)?,
            max_concurrent_servers: args
                .value_of("max-concurrent-servers")
                .map(|x| usize::from_str(x).context("failed to parse max-concurrent-servers"))
                .unwrap()?, // Safe unwrap, because clap's validation
            ignore_system_resolv_opt: args.is_present("no-system-resolv-opt"),
            attempts: args
                .value_of("attempts")
                .map(|x| usize::from_str(x).context("failed to parse attempts"))
                .unwrap()?, // Safe unwrap, because clap's validation
            max_concurrent_requests: args
                .value_of("max-concurrent-requests")
                .map(|x| usize::from_str(x).context("max-concurrent-requests"))
                .unwrap()?, // Safe unwrap, because clap's validation
            timeout: args
                .value_of("timeout")
                .map(|x| u64::from_str(x).map(Duration::from_secs).context("failed to parse timeout"))
                .unwrap()?, // Safe unwrap, because clap's validation
            expects_multiple_responses: args.is_present("wait-multiple-responses"),
            abort_on_error: !(args.is_present("no-abort-on-error") || args.is_present("no-aborts")),
            abort_on_timeout: !(args.is_present("no-abort-on-timeout") || args.is_present("no-aborts")),
            resolv_conf_path: args.value_of("resolv-conf").unwrap_or("/etc/resolv.conf").to_string(),
            quiet: args.is_present("quiet"),
            ignore_system_nameservers: args.is_present("no-system-nameservers"),
            nameservers: args.values_of("nameservers").map(|xs| xs.into_iter().map(ToString::to_string).collect()),
            predefined: args.is_present("predefined"),
            predefined_filter: args.values_of("predefined-filter").map(|xs| xs.into_iter().map(ToString::to_string).collect()),
            nameserver_file_path: args.value_of("nameservers-from-file").map(ToString::to_string),
            randomized_lookup: args.is_present("randomized-lookup"),
            system_nameservers: args.values_of("system nameservers").map(|xs| xs.into_iter().map(ToString::to_string).collect()),
        };

        Ok(config)
    }
}

impl Config {
    pub fn resolver_opts(&self, default_opts: ResolverOpts) -> ResolverOpts {
        ResolverOpts {
            attempts: self.attempts,
            max_concurrent_requests: self.max_concurrent_requests,
            timeout: self.timeout,
            expects_multiple_responses: self.expects_multiple_responses,
            abort_on_error: self.abort_on_error,
            abort_on_timeout: self.abort_on_timeout,
            ..default_opts
        }
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

fn parse_record_types<'a, I: Iterator<Item=&'a str>>(record_types: I) -> Result<Vec<RecordType>> {
    let record_types: Vec<_> = record_types
        .map(str::to_uppercase)
        .map(|x| RecordType::from_str(&x))
        .collect();
    let record_types: std::result::Result<Vec<_>, _> = record_types.into_iter().collect();
    record_types.context("Failed to parse record type")
}