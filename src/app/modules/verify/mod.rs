// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::convert::TryInto;

use anyhow::Result;
use clap::ArgMatches;
use tracing::info;

use config::VerifyConfig;
use verify::Verify;

use crate::app::modules::PartialResultExt;
use crate::app::AppConfig;
use crate::app::ExitStatus;

pub mod config;
#[allow(clippy::module_inception)]
pub mod verify;

pub async fn run(args: &ArgMatches, app_config: &AppConfig) -> Result<ExitStatus> {
    info!("verify module selected.");
    let args = args.subcommand_matches("verify").unwrap();
    let config: VerifyConfig = args.try_into()?;

    Verify::init(app_config, &config)
        .await?
        .compare()
        .output()
        .into_result()
}
