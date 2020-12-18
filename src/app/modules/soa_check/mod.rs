use anyhow::Result;
use clap::ArgMatches;
use std::convert::TryInto;
use tracing::info;

use crate::app::modules::PartialResultExt;
use crate::app::AppConfig;
use crate::app::ExitStatus;

pub mod config;
#[allow(clippy::module_inception)]
mod soa_check;

use config::SoaCheckConfig;
use soa_check::SoaCheck;

pub async fn run(args: &ArgMatches<'_>, app_config: &AppConfig) -> Result<ExitStatus> {
    info!("soa-check module selected.");
    let args = args.subcommand_matches("soa-check").unwrap();
    let config: SoaCheckConfig = args.try_into()?;

    SoaCheck::init(app_config, &config)
        .await?
        .lookup_authoritative_name_servers()
        .await?
        .lookup_name_server_ips()
        .await?
        .lookup_soa_records()
        .await?
        .output()
        .into_result()
}
