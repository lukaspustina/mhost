// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

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

pub async fn run(args: &ArgMatches, app_config: &AppConfig) -> Result<ExitStatus> {
    info!("check module selected.");
    let args = args.subcommand_matches("check").unwrap();
    let config: CheckConfig = args.try_into()?;

    Check::init(app_config, &config)
        .await?
        .lookup_all_records()
        .await?
        .soa()
        .await?
        .ns()
        .await?
        .delegation()
        .await?
        .cnames()
        .await?
        .mx()
        .await?
        .https_svcb()
        .await?
        .spf()?
        .dmarc()
        .await?
        .caa()?
        .ttl()?
        .dnssec()?
        .axfr()
        .await?
        .open_resolver()
        .await?
        .output()
        .into_result()
}
