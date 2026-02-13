// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::convert::TryFrom;

use crate::app::modules::ModConfig;
use crate::services::server_lists::ServerListSpec;
use anyhow::Context;
use clap::ArgMatches;
use std::str::FromStr;

pub struct DownloadServerListConfig {
    pub server_list_specs: Vec<ServerListSpec>,
    pub output_file_path: String,
}

impl ModConfig for DownloadServerListConfig {}

impl TryFrom<&ArgMatches> for DownloadServerListConfig {
    type Error = anyhow::Error;

    fn try_from(args: &ArgMatches) -> std::result::Result<Self, Self::Error> {
        let server_list_specs: Vec<_> = args
            .get_many::<String>("server_list_spec")
            .context("No server list specification")?
            .map(|s| ServerListSpec::from_str(s))
            .collect();
        let server_list_specs: std::result::Result<Vec<_>, _> = server_list_specs.into_iter().collect();
        let server_list_specs = server_list_specs?;
        let config = DownloadServerListConfig {
            server_list_specs,
            output_file_path: args
                .get_one::<String>("output-file")
                .context("No output file name specified")?
                .to_string(),
        };

        Ok(config)
    }
}
