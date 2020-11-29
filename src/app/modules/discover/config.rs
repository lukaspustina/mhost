use std::convert::TryFrom;

use anyhow::Context;
use clap::ArgMatches;

pub struct DiscoverConfig {
    pub domain_name: String,
    pub partial_results: bool,
    pub single_server_lookup: bool,
}

impl TryFrom<&ArgMatches<'_>> for DiscoverConfig {
    type Error = anyhow::Error;

    fn try_from(args: &ArgMatches) -> std::result::Result<Self, Self::Error> {
        let config = DiscoverConfig {
            domain_name: args
                .value_of("domain name")
                .context("No domain name to lookup specified")?
                .to_string(),
            partial_results: args.is_present("partial-results"),
            single_server_lookup: args.is_present("single-server-lookup"),
        };

        Ok(config)
    }
}
