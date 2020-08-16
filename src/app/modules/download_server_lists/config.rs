use std::convert::TryFrom;

use crate::services::server_lists::ServerListSpec;
use anyhow::Context;
use clap::ArgMatches;
use std::str::FromStr;

pub struct DownloadServerListConfig {
    pub server_list_specs: Vec<ServerListSpec>,
    pub output_file_path: String,
}

impl TryFrom<&ArgMatches<'_>> for DownloadServerListConfig {
    type Error = anyhow::Error;

    fn try_from(args: &ArgMatches) -> std::result::Result<Self, Self::Error> {
        let server_list_specs: Vec<_> = args
            .values_of("server_list_spec")
            .context("No server list specification")?
            .map(ServerListSpec::from_str)
            .collect();
        let server_list_specs: std::result::Result<Vec<_>, _> = server_list_specs.into_iter().collect();
        let server_list_specs = server_list_specs?;
        let config = DownloadServerListConfig {
            server_list_specs,
            output_file_path: args
                .value_of("output-file")
                .context("No output file name specified")?
                .to_string(),
        };

        Ok(config)
    }
}
