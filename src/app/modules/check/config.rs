use std::convert::TryFrom;

use crate::app::modules::ModConfig;
use anyhow::Context;
use clap::ArgMatches;

pub struct CheckConfig {
    pub domain_name: String,
    pub partial_results: bool,
    pub show_intermediate_lookups: bool,
    pub cnames: bool,
    pub soa: bool,
    pub spf: bool,
}

impl ModConfig for CheckConfig {
    fn partial_results(&self) -> bool {
        self.partial_results
    }
}

impl TryFrom<&ArgMatches<'_>> for CheckConfig {
    type Error = anyhow::Error;

    fn try_from(args: &ArgMatches) -> std::result::Result<Self, Self::Error> {
        let config = CheckConfig {
            domain_name: args
                .value_of("domain name")
                .context("No domain name to lookup specified")?
                .to_string(),
            partial_results: args.is_present("partial-results"),
            show_intermediate_lookups: args.is_present("show-intermediate-lookups"),
            cnames: !args.is_present("no-cnames"),
            soa: !args.is_present("no-soa"),
            spf: !args.is_present("no-spf"),
        };

        Ok(config)
    }
}
