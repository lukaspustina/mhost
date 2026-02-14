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

use crate::app::modules::PartialResultExt;
use crate::app::AppConfig;
use crate::app::ExitStatus;

pub mod config;
#[allow(clippy::module_inception)]
mod domain_lookup;
pub mod subdomain_spec;

use config::DomainLookupConfig;
use domain_lookup::DomainLookup;

pub async fn run(args: &ArgMatches, app_config: &AppConfig) -> Result<ExitStatus> {
    info!("domain-lookup module selected.");
    let args = args.subcommand_matches("domain-lookup").unwrap();
    let config: DomainLookupConfig = args.try_into()?;

    DomainLookup::init(app_config, &config)
        .await?
        .lookups()
        .await?
        .output()
        .into_result()
}
