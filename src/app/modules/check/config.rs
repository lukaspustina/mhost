use std::convert::TryFrom;

use anyhow::Context;
use clap::ArgMatches;

pub struct CheckConfig {
    pub domain_name: String,
    pub partial_results: bool,
    pub spf: bool,
    pub record_type_lints: bool,
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
            spf: !args.is_present("no-spf"),
            record_type_lints: !args.is_present("no-record-type-lint"),
        };

        Ok(config)
    }
}
