use anyhow::Result;
use clap::ArgMatches;
use log::info;
use std::convert::TryInto;

use crate::app::console::ExitStatus;
use crate::app::AppConfig;

pub mod config;
#[allow(clippy::module_inception)]
mod discover;
mod wordlist;

use config::DiscoverConfig;
use discover::Discover;

pub async fn run(args: &ArgMatches<'_>, app_config: &AppConfig) -> Result<ExitStatus> {
    info!("discover module selected.");
    let args = args.subcommand_matches("discover").unwrap();
    let config: DiscoverConfig = args.try_into()?;

    Discover::init(app_config, &config)
        .await?
        .request_all_records()
        .await?
        .check_wildcard_resolution()
        .await?
        .wordlist_lookups()
        .await?
        .output()
}
