// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::app::modules::get_server_lists::config::DownloadServerListConfig;
use crate::app::modules::PartialResultExt;
use crate::app::AppConfig;
use crate::app::ExitStatus;

use anyhow::Result;
use clap::ArgMatches;
use std::convert::TryInto;
use tracing::info;

pub mod config;
#[allow(clippy::module_inception)]
mod get_server_lists;

use get_server_lists::GetServerLists;

pub async fn run(args: &ArgMatches<'_>, app_config: &AppConfig) -> Result<ExitStatus> {
    info!("server-lists module selected.");
    let args = args.subcommand_matches("server-lists").unwrap();
    let config: DownloadServerListConfig = args.try_into()?;

    GetServerLists::init(app_config, &config)?
        .download_server_lists()
        .await?
        .write_servers_to_file()
        .await
        .into_result()
}
