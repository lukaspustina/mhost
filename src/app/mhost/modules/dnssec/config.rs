// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::convert::TryFrom;

use anyhow::Context;
use clap::ArgMatches;

use crate::app::modules::ModConfig;

pub struct DnssecConfig {
    pub domain_name: String,
    pub max_hops: usize,
    pub partial_results: bool,
}

impl ModConfig for DnssecConfig {
    fn partial_results(&self) -> bool {
        self.partial_results
    }
}

impl TryFrom<&ArgMatches> for DnssecConfig {
    type Error = anyhow::Error;

    fn try_from(args: &ArgMatches) -> std::result::Result<Self, Self::Error> {
        let config = DnssecConfig {
            domain_name: args
                .get_one::<String>("domain name")
                .context("No domain name specified")?
                .to_string(),
            max_hops: *args.get_one::<usize>("max-hops").unwrap_or(&10),
            partial_results: args.get_flag("partial-results"),
        };

        Ok(config)
    }
}
