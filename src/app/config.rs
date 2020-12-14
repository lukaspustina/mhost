use std::convert::TryFrom;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::ArgMatches;

use crate::app::output::json::JsonOptions;
use crate::app::output::summary::SummaryOptions;
use crate::app::output::{OutputConfig, OutputType};
use crate::resolver::ResolverOpts;

pub struct AppConfig {
    pub list_predefined: bool,
    pub max_concurrent_servers: usize,
    pub ignore_system_resolv_opt: bool,
    pub retries: usize,
    pub max_concurrent_requests: usize,
    pub timeout: Duration,
    pub expects_multiple_responses: bool,
    pub abort_on_error: bool,
    pub abort_on_timeout: bool,
    pub resolv_conf_path: String,
    pub show_errors: bool,
    pub quiet: bool,
    pub ignore_system_nameservers: bool,
    pub nameservers: Option<Vec<String>>,
    pub predefined: bool,
    pub predefined_filter: Option<Vec<String>>,
    pub nameserver_file_path: Option<String>,
    pub limit: usize,
    pub system_nameservers: Option<Vec<String>>,
    pub output: OutputType,
    pub output_config: OutputConfig,
}

impl TryFrom<&ArgMatches<'_>> for AppConfig {
    type Error = anyhow::Error;

    fn try_from(args: &ArgMatches) -> std::result::Result<Self, Self::Error> {
        let output = args
            .value_of("output")
            .map(|x| OutputType::try_from(x).context("failed to parse output type"))
            .unwrap()?; // Safe unwrap, because of clap's validation
        let config = AppConfig {
            list_predefined: args.is_present("list-predefined"),
            max_concurrent_servers: args
                .value_of("max-concurrent-servers")
                .map(|x| usize::from_str(x).context("failed to parse max-concurrent-servers"))
                .unwrap()?, // Safe unwrap, because clap's validation
            ignore_system_resolv_opt: args.is_present("no-system-resolv-opt"),
            retries: args
                .value_of("retries")
                .map(|x| usize::from_str(x).context("failed to parse retries"))
                .unwrap()?, // Safe unwrap, because clap's validation
            max_concurrent_requests: args
                .value_of("max-concurrent-requests")
                .map(|x| usize::from_str(x).context("max-concurrent-requests"))
                .unwrap()?, // Safe unwrap, because clap's validation
            timeout: args
                .value_of("timeout")
                .map(|x| {
                    u64::from_str(x)
                        .map(Duration::from_secs)
                        .context("failed to parse timeout")
                })
                .unwrap()?, // Safe unwrap, because clap's validation
            expects_multiple_responses: args.is_present("wait-multiple-responses"),
            abort_on_error: !(args.is_present("no-abort-on-error") || args.is_present("no-aborts")),
            abort_on_timeout: !(args.is_present("no-abort-on-timeout") || args.is_present("no-aborts")),
            resolv_conf_path: args.value_of("resolv-conf").unwrap_or("/etc/resolv.conf").to_string(),
            show_errors: args.is_present("show-errors"),
            quiet: args.is_present("quiet"),
            ignore_system_nameservers: args.is_present("no-system-nameservers"),
            nameservers: args
                .values_of("nameservers")
                .map(|xs| xs.map(ToString::to_string).collect()),
            predefined: args.is_present("predefined"),
            predefined_filter: args
                .values_of("predefined-filter")
                .map(|xs| xs.map(ToString::to_string).collect()),
            nameserver_file_path: args.value_of("nameservers-from-file").map(ToString::to_string),
            limit: args
                .value_of("limit")
                .map(|x| usize::from_str(x).context("failed to parse limit"))
                .unwrap()?, // Safe unwrap, because clap's validation
            system_nameservers: args
                .values_of("system nameservers")
                .map(|xs| xs.map(ToString::to_string).collect()),
            output_config: output_config(output, &args)?,
            output,
        };

        Ok(config)
    }
}

impl AppConfig {
    pub fn resolver_opts(&self, default_opts: ResolverOpts) -> ResolverOpts {
        ResolverOpts {
            retries: self.retries,
            max_concurrent_requests: self.max_concurrent_requests,
            timeout: self.timeout,
            expects_multiple_responses: self.expects_multiple_responses,
            abort_on_error: self.abort_on_error,
            abort_on_timeout: self.abort_on_timeout,
            ..default_opts
        }
    }
}

fn output_config(output_type: OutputType, args: &ArgMatches<'_>) -> Result<OutputConfig> {
    let args = args
        .values_of("output-options")
        .context("No output options specified")?;
    parse_output_options(output_type, args)
}

fn parse_output_options<'a, I: Iterator<Item = &'a str>>(output_type: OutputType, options: I) -> Result<OutputConfig> {
    let options: Vec<&str> = options.collect();
    match output_type {
        OutputType::Json => {
            let options = JsonOptions::try_from(options).context("failed to parse json options")?;
            Ok(OutputConfig::json(options))
        }
        OutputType::Summary => {
            let options = SummaryOptions::try_from(options).context("failed to parse json options")?;
            Ok(OutputConfig::summary(options))
        }
    }
}
