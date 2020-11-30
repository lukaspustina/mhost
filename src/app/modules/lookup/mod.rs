use std::convert::TryInto;

use anyhow::Result;
use clap::ArgMatches;
use log::info;

use crate::app::cli::ExitStatus;
use crate::app::GlobalConfig;

pub mod config;
#[allow(clippy::module_inception)]
mod lookup;

use config::LookupConfig;
use lookup::Lookup;

pub async fn run(args: &ArgMatches<'_>, global_config: &GlobalConfig) -> Result<ExitStatus> {
    info!("lookup module selected.");
    let args = args.subcommand_matches("lookup").unwrap();
    let config: LookupConfig = args.try_into()?;

    Lookup::init(global_config, &config)
        .await?
        .lookups()
        .await?
        .optional_whois()
        .await?
        .output()
}
