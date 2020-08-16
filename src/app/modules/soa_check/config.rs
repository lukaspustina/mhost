use std::convert::TryFrom;

use anyhow::Context;
use clap::ArgMatches;

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
