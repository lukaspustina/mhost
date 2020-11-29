use crate::app::cli::ExitStatus;
use crate::app::modules::get_server_lists::config::DownloadServerListConfig;
use crate::app::GlobalConfig;
use anyhow::Result;
use clap::ArgMatches;
use log::info;
use std::convert::TryInto;

pub mod config;
#[allow(clippy::module_inception)]
mod get_server_lists;

use get_server_lists::GetServerLists;

pub async fn run(args: &ArgMatches<'_>, global_config: &GlobalConfig) -> Result<ExitStatus> {
    info!("get-server-lists module selected.");
    let args = args.subcommand_matches("get-server-lists").unwrap();
    let config: DownloadServerListConfig = args.try_into()?;

    GetServerLists::init(global_config, config)?
        .download_server_lists()
        .await?
        .write_servers_to_file()
        .await
}
