// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::convert::TryFrom;

use crate::app::modules::ModConfig;
use anyhow::Context;
use clap::ArgMatches;
use std::str::FromStr;

pub struct DiscoverConfig {
    pub domain_name: String,
    pub partial_results: bool,
    pub wordlist_file_path: Option<String>,
    pub rnd_names_number: usize,
    pub rnd_names_len: usize,
    pub subdomains_only: bool,
}

impl ModConfig for DiscoverConfig {
    fn partial_results(&self) -> bool {
        self.partial_results
    }
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
            wordlist_file_path: args.value_of("wordlist-from-file").map(ToString::to_string),
            rnd_names_number: args
                .value_of("rnd-names-number")
                .map(|x| usize::from_str(x).context("failed to parse rnd-names-number"))
                .unwrap()?, // Safe unwrap, because of clap's validation
            rnd_names_len: args
                .value_of("rnd-names-len")
                .map(|x| usize::from_str(x).context("failed to parse rnd-names-len"))
                .unwrap()?, // Safe unwrap, because of clap's validation
            subdomains_only: args.is_present("subdomains-only"),
        };

        Ok(config)
    }
}
