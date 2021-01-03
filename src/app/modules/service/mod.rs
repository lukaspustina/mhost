use std::convert::TryInto;

use anyhow::Result;
use clap::ArgMatches;
use tracing::info;

use config::ServiceConfig;

use crate::app::modules::lookup::lookup::Lookup;
use crate::app::modules::PartialResultExt;
use crate::app::AppConfig;
use crate::app::ExitStatus;

pub mod config;
mod parser;

pub async fn run(args: &ArgMatches<'_>, app_config: &AppConfig) -> Result<ExitStatus> {
    info!("service module selected.");
    let args = args.subcommand_matches("service").unwrap();
    let config: ServiceConfig = args.try_into()?;

    let domain_name = ServiceSpec::from_str(&config.service_spec)?.to_domain_name();
    info!(
        "Parsed service specification to domain name '{}' for lookup",
        domain_name
    );
    let config = config.into_lookup_config(domain_name);

    Lookup::init(app_config, &config)
        .await?
        .lookups()
        .await?
        .optional_whois()
        .await?
        .output()
        .into_result()
}

#[derive(Debug, PartialEq, Eq)]
pub struct ServiceSpec {
    service_name: String,
    protocol: String,
    domain_name: String,
}

impl ServiceSpec {
    pub(crate) fn new<S: Into<String>, T: Into<String>, U: Into<String>>(
        service_name: S,
        protocol: T,
        domain_name: U,
    ) -> ServiceSpec {
        ServiceSpec {
            service_name: service_name.into(),
            protocol: protocol.into(),
            domain_name: domain_name.into(),
        }
    }

    pub fn to_domain_name(&self) -> String {
        format!("_{}._{}.{}", &self.service_name, &self.protocol, &self.domain_name)
    }
}
