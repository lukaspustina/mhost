// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::convert::TryFrom;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result};
use clap::ArgMatches;

use crate::app::modules::ModConfig;
use crate::RecordType;

pub struct VerifyConfig {
    pub zone_file: PathBuf,
    pub origin: Option<String>,
    pub strict: bool,
    pub only_types: Option<Vec<RecordType>>,
    pub ignore_types: Option<Vec<RecordType>>,
    pub ignore_extra: bool,
    pub ignore_soa: bool,
}

impl ModConfig for VerifyConfig {}

impl TryFrom<&ArgMatches> for VerifyConfig {
    type Error = anyhow::Error;

    fn try_from(args: &ArgMatches) -> Result<Self> {
        let config = VerifyConfig {
            zone_file: args
                .get_one::<String>("zone-file")
                .context("No zone file specified")?
                .into(),
            origin: args.get_one::<String>("origin").cloned(),
            strict: args.get_flag("strict"),
            only_types: parse_record_types(args, "only-type")?,
            ignore_types: parse_record_types(args, "ignore-type")?,
            ignore_extra: args.get_flag("ignore-extra"),
            ignore_soa: args.get_flag("ignore-soa"),
        };

        Ok(config)
    }
}

fn parse_record_types(args: &ArgMatches, arg_name: &str) -> Result<Option<Vec<RecordType>>> {
    args.get_many::<String>(arg_name)
        .map(|values| {
            values
                .map(|s| RecordType::from_str(&s.to_uppercase()))
                .collect::<std::result::Result<Vec<_>, _>>()
                .context(format!("Failed to parse record type in --{arg_name}"))
        })
        .transpose()
}
