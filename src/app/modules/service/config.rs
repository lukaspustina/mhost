use std::convert::TryFrom;

use crate::app::modules::lookup::config::LookupConfig;
use crate::RecordType;
use anyhow::Context;
use clap::ArgMatches;

pub struct ServiceConfig {
    pub service_spec: String,
}

impl TryFrom<&ArgMatches<'_>> for ServiceConfig {
    type Error = anyhow::Error;

    fn try_from(args: &ArgMatches) -> std::result::Result<Self, Self::Error> {
        let config = ServiceConfig {
            service_spec: args
                .value_of("service spec")
                .context("No service spec to lookup specified")?
                .to_string(),
        };

        Ok(config)
    }
}

impl ServiceConfig {
    pub fn into_lookup_config(self, domain_name: String) -> LookupConfig {
        LookupConfig {
            domain_name,
            record_types: vec![RecordType::SRV],
            whois: false,
        }
    }
}
