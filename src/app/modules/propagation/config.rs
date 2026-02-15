// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::convert::TryFrom;
use std::str::FromStr;

use anyhow::Context;
use clap::ArgMatches;

use crate::app::cli_parser::SUPPORTED_RECORD_TYPES;
use crate::app::modules::ModConfig;
use crate::RecordType;

pub struct PropagationConfig {
    pub domain_name: String,
    pub record_types: Vec<RecordType>,
}

impl ModConfig for PropagationConfig {
    fn partial_results(&self) -> bool {
        true
    }
}

impl TryFrom<&ArgMatches> for PropagationConfig {
    type Error = anyhow::Error;

    fn try_from(args: &ArgMatches) -> std::result::Result<Self, Self::Error> {
        let record_types = if args.get_flag("all-record-types") {
            SUPPORTED_RECORD_TYPES
                .iter()
                .filter(|x| **x != "ANY")
                .map(|x| RecordType::from_str(x).expect("SUPPORTED_RECORD_TYPES entries must be valid"))
                .collect()
        } else {
            let args: Vec<&str> = args
                .get_many::<String>("record-types")
                .context("No record types specified")?
                .map(|s| s.as_str())
                .collect();
            let record_types: Vec<_> = args
                .into_iter()
                .map(|x| x.to_uppercase())
                .map(|x| RecordType::from_str(&x))
                .collect();
            let record_types: std::result::Result<Vec<_>, _> = record_types.into_iter().collect();
            record_types.context("Failed to parse record type")?
        };

        let config = PropagationConfig {
            domain_name: args
                .get_one::<String>("domain name")
                .context("No domain name specified")?
                .to_string(),
            record_types,
        };

        Ok(config)
    }
}
