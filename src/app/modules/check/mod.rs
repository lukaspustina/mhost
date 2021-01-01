use anyhow::Result;
use clap::ArgMatches;
use std::convert::TryInto;
use tracing::info;

use crate::app::modules::PartialResultExt;
use crate::app::AppConfig;
use crate::app::ExitStatus;

pub mod config;
#[allow(clippy::module_inception)]
mod lints;

use config::CheckConfig;
use lints::Check;

pub async fn run(args: &ArgMatches<'_>, app_config: &AppConfig) -> Result<ExitStatus> {
    info!("check module selected.");
    let args = args.subcommand_matches("check").unwrap();
    let config: CheckConfig = args.try_into()?;

    Check::init(app_config, &config)
        .await?
        .lookup_all_records()
        .await?
        .cnames()
        .await?
        .spf()?
        .output()
        .into_result()
}