use crate::app::modules::get_server_lists::config::DownloadServerListConfig;
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
    info!("get-server-lists module selected.");
    let args = args.subcommand_matches("get-server-lists").unwrap();
    let config: DownloadServerListConfig = args.try_into()?;

    GetServerLists::init(app_config, &config)?
        .download_server_lists()
        .await?
        .write_servers_to_file()
        .await
}
