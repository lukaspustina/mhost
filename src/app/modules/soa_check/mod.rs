use anyhow::Result;
use clap::ArgMatches;
use log::info;
use std::convert::TryInto;

use crate::app::cli::ExitStatus;
use crate::app::GlobalConfig;

pub mod config;
#[allow(clippy::module_inception)]
pub mod soa_check;

use config::SoaCheckConfig;
use soa_check::SoaCheck;

pub async fn run(args: &ArgMatches<'_>, global_config: &GlobalConfig) -> Result<ExitStatus> {
    info!("soa-check module selected.");
    let args = args.subcommand_matches("soa-check").unwrap();
    let config: SoaCheckConfig = args.try_into()?;

    SoaCheck::new(global_config, &config)
        .await?
        .lookup_authoritative_name_servers()
        .await?
        .lookup_name_server_ips()
        .await?
        .lookup_soa_records()
        .await?
        .diff()
}
