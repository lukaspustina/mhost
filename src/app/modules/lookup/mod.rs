use std::convert::TryInto;

use anyhow::Result;
use clap::ArgMatches;
use log::info;

use crate::app::console::ExitStatus;
use crate::app::AppConfig;

pub mod config;
#[allow(clippy::module_inception)]
mod lookup;

use config::LookupConfig;
use lookup::Lookup;

pub async fn run(args: &ArgMatches<'_>, app_config: &AppConfig) -> Result<ExitStatus> {
    info!("lookup module selected.");
    let args = args.subcommand_matches("lookup").unwrap();
    let config: LookupConfig = args.try_into()?;

    Lookup::init(app_config, &config)
        .await?
        .lookups()
        .await?
        .optional_whois()
        .await?
        .output()
}
