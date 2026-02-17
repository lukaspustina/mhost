// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::convert::TryFrom;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::ArgMatches;

use crate::app::modules::ModConfig;

pub struct VerifyConfig {
    pub zone_file: PathBuf,
    pub origin: Option<String>,
    pub strict: bool,
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
        };

        Ok(config)
    }
}
