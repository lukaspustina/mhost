use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Instant;

use anyhow::Result;
use indexmap::set::IndexSet;
use log::info;

use crate::app::cli::{print_estimates_lookups, print_opts, print_statistics, ExitStatus};
use crate::app::modules::discover::config::DiscoverConfig;
use crate::app::resolver::AppResolver;
use crate::app::{output, GlobalConfig, ModuleStep};
use crate::diff::SetDiffer;
use crate::nameserver::NameServerConfig;
use crate::output::styles::{self, ATTENTION_PREFIX, CAPTION_PREFIX, ERROR_PREFIX, OK_PREFIX};
use crate::resolver::lookup::Uniquify;
use crate::resolver::{MultiQuery, ResolverConfig};
use crate::resources::rdata::SOA;
use crate::{Name, RecordType};

pub struct Discover {}

impl Discover {
    pub async fn init<'a>(global_config: &'a GlobalConfig, config: &'a DiscoverConfig) -> Result<ExitStatus> {
        let query = MultiQuery::single(config.domain_name.as_str(), RecordType::NS)?;
        let app_resolver = AppResolver::create_resolvers(global_config).await?;

        Ok(ExitStatus::Ok)
    }
}
