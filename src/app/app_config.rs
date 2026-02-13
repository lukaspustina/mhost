// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::convert::TryFrom;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::ArgMatches;

use crate::app::output::json::JsonOptions;
use crate::app::output::summary::SummaryOptions;
use crate::app::output::{OutputConfig, OutputType};
use crate::resolver::Mode;

#[derive(Debug)]
pub struct AppConfig {
    pub list_predefined: bool,
    pub max_concurrent_servers: usize,
    pub use_system_resolv_opt: bool,
    pub retries: usize,
    pub max_concurrent_requests: usize,
    pub timeout: Duration,
    pub expects_multiple_responses: bool,
    pub abort_on_error: bool,
    pub abort_on_timeout: bool,
    pub resolv_conf_path: String,
    pub ndots: u8,
    pub search_domain: Option<String>,
    pub show_errors: bool,
    pub quiet: bool,
    pub ignore_system_nameservers: bool,
    pub no_system_lookups: bool,
    pub nameservers: Option<Vec<String>>,
    pub predefined: bool,
    pub predefined_filter: Option<Vec<String>>,
    pub nameserver_file_path: Option<String>,
    pub limit: usize,
    pub system_nameservers: Option<Vec<String>>,
    pub resolvers_mode: Mode,
    pub output: OutputType,
    pub output_config: OutputConfig,
    #[doc(hidden)]
    pub max_worker_threads: Option<usize>,
}

impl AppConfig {
    #[doc(hidden)]
    pub fn max_worker_threads(&self) -> Option<usize> {
        self.max_worker_threads
    }
}

impl TryFrom<&ArgMatches> for AppConfig {
    type Error = anyhow::Error;

    fn try_from(args: &ArgMatches) -> std::result::Result<Self, Self::Error> {
        let output = args
            .get_one::<String>("output")
            .map(|x| OutputType::try_from(x.as_str()).context("failed to parse output type"))
            .unwrap()?; // Safe unwrap, because of clap's validation
        let config = AppConfig {
            list_predefined: args.get_flag("list-predefined"),
            max_concurrent_servers: *args
                .get_one::<usize>("max-concurrent-servers")
                .unwrap(), // Safe unwrap, because clap's validation
            use_system_resolv_opt: args.get_flag("use-system-resolv-opt"),
            retries: *args
                .get_one::<usize>("retries")
                .unwrap(), // Safe unwrap, because clap's validation
            max_concurrent_requests: *args
                .get_one::<usize>("max-concurrent-requests")
                .unwrap(), // Safe unwrap, because clap's validation
            timeout: {
                let secs = *args.get_one::<u64>("timeout").unwrap(); // Safe unwrap, because clap's validation
                Duration::from_secs(secs)
            },
            expects_multiple_responses: args.get_flag("wait-multiple-responses"),
            abort_on_error: !(args.get_flag("no-abort-on-error") || args.get_flag("no-aborts")),
            abort_on_timeout: !(args.get_flag("no-abort-on-timeout") || args.get_flag("no-aborts")),
            resolv_conf_path: args
                .get_one::<String>("resolv-conf")
                .map(|s| s.as_str())
                .unwrap_or("/etc/resolv.conf")
                .to_string(),
            ndots: *args
                .get_one::<u8>("ndots")
                .unwrap(), // Safe unwrap, because clap's validation
            search_domain: args.get_one::<String>("search-domain").map(ToString::to_string),
            show_errors: args.get_flag("show-errors"),
            quiet: args.get_flag("quiet"),
            ignore_system_nameservers: args.get_flag("no-system-nameservers"),
            no_system_lookups: args.get_flag("no-system-lookups"),
            nameservers: args
                .get_many::<String>("nameservers")
                .map(|xs| xs.map(ToString::to_string).collect()),
            predefined: args.get_flag("predefined"),
            predefined_filter: args
                .get_many::<String>("predefined-filter")
                .map(|xs| xs.map(ToString::to_string).collect()),
            nameserver_file_path: args.get_one::<String>("nameservers-from-file").map(ToString::to_string),
            limit: *args
                .get_one::<usize>("limit")
                .unwrap(), // Safe unwrap, because clap's validation
            system_nameservers: args
                .get_many::<String>("system nameservers")
                .map(|xs| xs.map(ToString::to_string).collect()),
            resolvers_mode: {
                let mode_str = args.get_one::<String>("resolvers-mode").unwrap(); // Safe unwrap, because clap's validation
                Mode::from_str(mode_str)?
            },
            output_config: output_config(output, args)?,
            output,
            max_worker_threads: args
                .get_one::<usize>("max-worker-threads")
                .copied(),
        };

        Ok(config)
    }
}

fn output_config(output_type: OutputType, args: &ArgMatches) -> Result<OutputConfig> {
    let args: Vec<&str> = args
        .get_many::<String>("output-options")
        .context("No output options specified")?
        .map(|s| s.as_str())
        .collect();
    parse_output_options(output_type, args.into_iter())
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
