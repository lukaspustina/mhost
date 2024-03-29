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

pub struct LookupConfig {
    pub domain_name: String,
    pub record_types: Vec<RecordType>,
    pub whois: bool,
    pub parse_as_service: bool,
}

impl ModConfig for LookupConfig {
    /// The Lookup module should always show partial results
    fn partial_results(&self) -> bool {
        true
    }
}

impl TryFrom<&ArgMatches<'_>> for LookupConfig {
    type Error = anyhow::Error;

    fn try_from(args: &ArgMatches) -> std::result::Result<Self, Self::Error> {
        let config = LookupConfig {
            domain_name: args
                .value_of("domain name")
                .context("No domain name to lookup specified")?
                .to_string(),
            record_types: record_types(args)?,
            whois: args.is_present("whois"),
            parse_as_service: args.is_present("parse-as-service"),
        };

        Ok(config)
    }
}

fn record_types(args: &ArgMatches<'_>) -> Result<Vec<RecordType>> {
    if args.is_present("all-record-types") {
        Ok(SUPPORTED_RECORD_TYPES
            .iter()
            .filter(|x| **x != "ANY")
            .map(|x| RecordType::from_str(x).unwrap())
            .collect())
    } else {
        let args = args
            .values_of("record-types")
            .context("No record types for name lookup specified")?;
        parse_record_types(args)
    }
}

fn parse_record_types<'a, I: Iterator<Item = &'a str>>(record_types: I) -> Result<Vec<RecordType>> {
    let record_types: Vec<_> = record_types
        .map(str::to_uppercase)
        .map(|x| RecordType::from_str(&x))
        .collect();
    let record_types: std::result::Result<Vec<_>, _> = record_types.into_iter().collect();
    record_types.context("Failed to parse record type")
}
