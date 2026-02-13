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

impl TryFrom<&ArgMatches> for DiscoverConfig {
    type Error = anyhow::Error;

    fn try_from(args: &ArgMatches) -> std::result::Result<Self, Self::Error> {
        let config = DiscoverConfig {
            domain_name: args
                .get_one::<String>("domain name")
                .context("No domain name to lookup specified")?
                .to_string(),
            partial_results: args.get_flag("partial-results"),
            wordlist_file_path: args.get_one::<String>("wordlist-from-file").map(ToString::to_string),
            rnd_names_number: *args
                .get_one::<usize>("rnd-names-number")
                .unwrap(), // Safe unwrap, because of clap's validation
            rnd_names_len: *args
                .get_one::<usize>("rnd-names-len")
                .unwrap(), // Safe unwrap, because of clap's validation
            subdomains_only: args.get_flag("subdomains-only"),
        };

        Ok(config)
    }
}
