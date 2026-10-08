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
            match self.dnskey_rrsigs().await? {
                Ok(rrsigs) => check_dnssec(&lookups.clone().merge(rrsigs)),
                Err(reason) => {
                    debug!("DNSKEY signatures not fetched: {}", reason);
                    let mut results = check_dnssec(lookups);
                    results.push(CheckResult::Warning(format!(
                        "{}: cannot check DNSKEY signatures",
                        reason
                    )));
                    results
                }
            }
        };

        print_check_results!(self, results, "No DNSSEC records found.");

        Ok(results)
    }

    /// Fetches the DNSKEY RRSIGs from the zone's own nameservers with DO set. Ordinary lookups
    /// cannot see them: the stub resolver strips RRSIGs unless the query sets DO.
    /// `Err` carries the reason when the zone's nameservers have no public address to ask.
    async fn dnskey_rrsigs(&self) -> PartialResult<std::result::Result<Lookups, String>> {
        let ns_names: Vec<Name> = self
            .check_results
            .lookups
            .ns()
            .unique()
            .to_owned()
            .into_iter()
            .collect();
        let Ok(query) = MultiQuery::new(ns_names, vec![RecordType::A, RecordType::AAAA]) else {
            return Ok(Ok(Lookups::empty()));
        };
        let ns_lookups: Lookups =
            intermediate_lookups!(self, query, "Resolving NS IP addresses for DNSKEY signatures.");

        let targets = match super::probe_targets(&ns_lookups, &self.env.console) {
            Ok(targets) => targets,
            Err(reason) => return Ok(Err(reason)),
        };
        let domain = self.domain_name.as_proto().clone();
        let signed = first_signed(&targets, |server| {
            let domain = domain.clone();
            async move {
                raw::raw_dnssec_query(server, &domain, RecordType::DNSKEY.to_proto(), Duration::from_secs(5)).await
            }
        })
        .await;
        if let Some((server, records)) = signed {
            let query = UniQuery::new(self.domain_name.clone(), RecordType::RRSIG)?;
            let name_server = Arc::new(NameServerConfig::udp(server));
            return Ok(Ok(Lookups::new(vec![Lookup::from_records(
                query,
                name_server,
                records,
            )])));
        }

        Ok(Ok(Lookups::empty()))
    }
}

/// The DNSKEY signatures from the first of up to three `targets` that answers with any. A lame or
/// refusing server answers without signatures; the next one is asked rather than judging the zone
/// by its silence.
async fn first_signed<F, Fut>(targets: &[std::net::IpAddr], mut query: F) -> Option<(SocketAddr, Vec<Record>)>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = raw::RawResult<raw::RawResponse>>,
{
    for ip in targets.iter().take(3) {
        let server = SocketAddr::new(*ip, 53);
        match query(server).await {
            Ok(response) => {
                let records = dnskey_signatures(&response);
                if records.is_empty() {
                    debug!(
                        "No DNSKEY signatures from {} (rcode {:?})",
                        server,
                        response.response_code()
                    );
                    continue;
                }
                info!("Received {} DNSKEY signatures from {}", records.len(), server);
                return Some((server, records));
            }
            Err(e) => debug!("DNSKEY query with DO failed against {}: {}", server, e),
        }
    }
    None
}

/// The RRSIG records in a DNSKEY response's answer section.
fn dnskey_signatures(response: &raw::RawResponse) -> Vec<Record> {
    response
        .answers()
        .iter()
        .map(Record::from_proto)
        .filter(|r| r.record_type() == RecordType::RRSIG)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::op::{Message, MessageType, OpCode, ResponseCode};

    fn signed_response() -> raw::RawResponse {
        use hickory_resolver::proto::dnssec::rdata::{sig::SigInput, DNSSECRData, RRSIG};
        use hickory_resolver::proto::dnssec::Algorithm;
        use hickory_resolver::proto::rr::SerialNumber;
        use hickory_resolver::proto::rr::{Name as ProtoName, RData as ProtoRData, Record as ProtoRecord};

        let zone = ProtoName::from_ascii("example.com.").unwrap();
        let input = SigInput {
            type_covered: RecordType::DNSKEY.to_proto(),
            algorithm: Algorithm::ECDSAP256SHA256,
            num_labels: 2,
            original_ttl: 3600,
            sig_expiration: SerialNumber::new(2_000_000_000),
            sig_inception: SerialNumber::new(1_900_000_000),
            key_tag: 2371,
            signer_name: zone.clone(),
        };
        let rrsig = ProtoRData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, vec![1, 2, 3])));
        let mut message = Message::new(1, MessageType::Response, OpCode::Query);
        message.add_answer(ProtoRecord::from_rdata(zone, 3600, rrsig));
        raw::RawResponse::new_for_test(message, Duration::from_millis(1))
    }

    #[tokio::test]
    async fn refusing_server_is_passed_over_for_the_next() {
        let targets: Vec<std::net::IpAddr> = vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()];
        let (server, records) = first_signed(&targets, |server| async move {
            if server.ip() == targets_first() {
                let mut message = Message::new(1, MessageType::Response, OpCode::Query);
                message.metadata.response_code = ResponseCode::Refused;
                Ok(raw::RawResponse::new_for_test(message, Duration::from_millis(1)))
            } else {
                Ok(signed_response())
            }
        })
        .await
        .expect("the second server answers with signatures");
        assert_eq!(server.ip(), "192.0.2.2".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(records.len(), 1);
    }

    fn targets_first() -> std::net::IpAddr {
        "192.0.2.1".parse().unwrap()
    }

    #[test]
    fn refusing_server_yields_no_signatures() {
        let mut message = Message::new(1, MessageType::Response, OpCode::Query);
        message.metadata.response_code = ResponseCode::Refused;
        let response = raw::RawResponse::new_for_test(message, Duration::from_millis(1));
        assert!(dnskey_signatures(&response).is_empty());
    }
}
