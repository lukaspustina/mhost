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

pub struct CheckConfig {
    pub domain_name: String,
    pub partial_results: bool,
    pub show_intermediate_lookups: bool,
    pub cnames: bool,
    pub soa: bool,
    pub spf: bool,
    pub dmarc: bool,
    pub ns: bool,
    pub mx: bool,
    pub caa: bool,
    pub ttl: bool,
    pub dnssec: bool,
    pub https_svcb: bool,
}

impl ModConfig for CheckConfig {
    fn partial_results(&self) -> bool {
        self.partial_results
    }
}

impl TryFrom<&ArgMatches> for CheckConfig {
    type Error = anyhow::Error;

    fn try_from(args: &ArgMatches) -> std::result::Result<Self, Self::Error> {
        let config = CheckConfig {
            domain_name: args
                .get_one::<String>("domain name")
                .context("No domain name to lookup specified")?
                .to_string(),
            partial_results: args.get_flag("partial-results"),
            show_intermediate_lookups: args.get_flag("show-intermediate-lookups"),
            cnames: !args.get_flag("no-cnames"),
            soa: !args.get_flag("no-soa"),
            spf: !args.get_flag("no-spf"),
            dmarc: !args.get_flag("no-dmarc"),
            ns: !args.get_flag("no-ns"),
            mx: !args.get_flag("no-mx"),
            caa: !args.get_flag("no-caa"),
            ttl: !args.get_flag("no-ttl"),
            dnssec: !args.get_flag("no-dnssec"),
            https_svcb: !args.get_flag("no-https-svcb"),
        };

        Ok(config)
    }
}
