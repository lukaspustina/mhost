// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info};

use crate::app::modules::check::config::CheckConfig;
use crate::app::modules::check::lints::axfr::Axfr;
use crate::app::modules::check::lints::{CheckResult, CheckResults};
use crate::app::modules::{Environment, PartialResult};
use crate::app::resolver::AppResolver;
use crate::app::utils::time;
use crate::nameserver::NameServerConfig;
use crate::resolver::lookup::{Lookup, Uniquify};
use crate::resolver::{raw, Lookups, MultiQuery, UniQuery};
use crate::resources::Record;
use crate::{Name, RecordType};

use super::check_dnssec;

pub struct DnssecCheck<'a> {
    pub env: Environment<'a, CheckConfig>,
    pub domain_name: Name,
    pub app_resolver: AppResolver,
    pub check_results: CheckResults,
}

impl<'a> DnssecCheck<'a> {
    pub async fn dnssec(self) -> PartialResult<Axfr<'a>> {
        let result = if self.env.mod_config.dnssec {
            Some(self.do_dnssec().await?)
        } else {
            None
        };

        Ok(Axfr {
            env: self.env,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            check_results: self.check_results.dnssec(result),
        })
    }

    async fn do_dnssec(&self) -> PartialResult<Vec<CheckResult>> {
        if self.env.console.show_partial_headers() {
            self.env.console.caption("Checking DNSSEC lints");
        }

        let lookups = &self.check_results.lookups;
        let results = if lookups.dnskey().is_empty() {
            check_dnssec(lookups)
        } else {
            let rrsigs = self.dnskey_rrsigs().await?;
            check_dnssec(&lookups.clone().merge(rrsigs))
        };

        print_check_results!(self, results, "No DNSSEC records found.");

        Ok(results)
    }

    /// Fetches the DNSKEY RRSIGs from the zone's own nameservers with DO set. Ordinary lookups
    /// cannot see them: the stub resolver strips RRSIGs unless the query sets DO.
    async fn dnskey_rrsigs(&self) -> PartialResult<Lookups> {
        let ns_names: Vec<Name> = self
            .check_results
            .lookups
            .ns()
            .unique()
            .to_owned()
            .into_iter()
            .collect();
        let Ok(query) = MultiQuery::new(ns_names, vec![RecordType::A, RecordType::AAAA]) else {
            return Ok(Lookups::empty());
        };
        let ns_lookups: Lookups =
            intermediate_lookups!(self, query, "Resolving NS IP addresses for DNSKEY signatures.");

        for ip in super::probe_targets(&ns_lookups, &self.env.console).into_iter().take(3) {
            let server = SocketAddr::new(ip, 53);
            match raw::raw_dnssec_query(
                server,
                self.domain_name.as_proto(),
                RecordType::DNSKEY.to_proto(),
                Duration::from_secs(5),
            )
            .await
            {
                Ok(response) => {
                    let records: Vec<Record> = response
                        .answers()
                        .iter()
                        .map(Record::from_proto)
                        .filter(|r| r.record_type() == RecordType::RRSIG)
                        .collect();
                    info!("Received {} DNSKEY signatures from {}", records.len(), server);
                    let query = UniQuery::new(self.domain_name.clone(), RecordType::RRSIG)?;
                    let name_server = Arc::new(NameServerConfig::udp(server));
                    return Ok(Lookups::new(vec![Lookup::from_records(query, name_server, records)]));
                }
                Err(e) => debug!("DNSKEY query with DO failed against {}: {}", server, e),
            }
        }

        Ok(Lookups::empty())
    }
}
