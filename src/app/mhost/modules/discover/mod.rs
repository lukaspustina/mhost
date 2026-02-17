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
pub mod discover;

// Re-export discover strategies from common
pub use crate::app::common::discover::ct_logs;
pub use crate::app::common::discover::permutation;
pub use crate::app::common::discover::srv_probing;
pub use crate::app::common::discover::txt_mining;
pub use crate::app::common::discover::wordlist;
pub use crate::app::common::discover::{filter_wildcard_responses, rnd_names};

use config::DiscoverConfig;
use discover::Discover;

pub async fn run(args: &ArgMatches, app_config: &AppConfig) -> Result<ExitStatus> {
    info!("discover module selected.");
    let args = args.subcommand_matches("discover").unwrap();
    let config: DiscoverConfig = args.try_into()?;

    Discover::init(app_config, &config)
        .await?
        .request_all_records()
        .await?
        .ct_log_query()
        .await?
        .txt_record_mining()
        .await?
        .srv_service_probing()
        .await?
        .check_wildcard_resolution()
        .await?
        .axfr_attempt()
        .await?
        .nsec_walking()
        .await?
        .wordlist_lookups()
        .await?
        .subdomain_permutation()
        .await?
        .recursive_depth_discovery()
        .await?
        .reverse_dns_lookups()
        .await?
        .output()
        .into_result()
}
