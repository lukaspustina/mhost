// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::convert::TryFrom;
use std::str::FromStr;

use anyhow::{Context, Result};
use clap::ArgMatches;

use crate::app::cli_parser::SUPPORTED_RECORD_TYPES;
use crate::app::modules::ModConfig;
use crate::RecordType;

pub struct DiffConfig {
    pub domain_name: String,
    pub record_types: Vec<RecordType>,
    pub left: Vec<String>,
    pub right: Vec<String>,
    pub left_file: Option<String>,
    pub right_file: Option<String>,
}

impl ModConfig for DiffConfig {
    fn partial_results(&self) -> bool {
        true
    }
}

impl TryFrom<&ArgMatches> for DiffConfig {
    type Error = anyhow::Error;

    fn try_from(args: &ArgMatches) -> std::result::Result<Self, Self::Error> {
        let left_file = args.get_one::<String>("left-from-file").cloned();
        let right_file = args.get_one::<String>("right-from-file").cloned();

        let config = DiffConfig {
            domain_name: args
                .get_one::<String>("domain name")
                .context("No domain name specified")?
                .to_string(),
            record_types: record_types(args)?,
            left: args
                .get_many::<String>("left")
                .map(|v| v.map(ToString::to_string).collect())
                .unwrap_or_default(),
            right: args
                .get_many::<String>("right")
                .map(|v| v.map(ToString::to_string).collect())
                .unwrap_or_default(),
            left_file,
            right_file,
        };

        Ok(config)
    }
}

fn record_types(args: &ArgMatches) -> Result<Vec<RecordType>> {
    if args.get_flag("all-record-types") {
        Ok(SUPPORTED_RECORD_TYPES
            .iter()
            .filter(|x| **x != "ANY")
            .map(|x| RecordType::from_str(x).expect("SUPPORTED_RECORD_TYPES entries must be valid"))
            .collect())
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
        record_types.context("Failed to parse record type")
    }
}
