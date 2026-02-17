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

pub struct DomainLookupConfig {
    pub domain_name: String,
    pub partial_results: bool,
    pub include_all: bool,
}

impl ModConfig for DomainLookupConfig {
    fn partial_results(&self) -> bool {
        self.partial_results
    }
}

impl TryFrom<&ArgMatches> for DomainLookupConfig {
    type Error = anyhow::Error;

    fn try_from(args: &ArgMatches) -> std::result::Result<Self, Self::Error> {
        let config = DomainLookupConfig {
            domain_name: args
                .get_one::<String>("domain name")
                .context("No domain name specified")?
                .to_string(),
            partial_results: args.get_flag("partial-results"),
            include_all: args.get_flag("all-entries"),
        };

        Ok(config)
    }
}
