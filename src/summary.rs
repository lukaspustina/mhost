// TODO: deny missing docs
#![allow(missing_docs)]

use dns::{Response, Result as LookupResult, Error as LookupError, Source};

use itertools::Itertools;
use std::collections::HashMap;
use trust_dns::rr::{RData, Record};

#[derive(Debug)]
pub struct RecordCount<'a> {
    record: &'a Record,
    sources: Vec<Source>,
}

impl<'a> RecordCount<'a> {
    pub fn count(&self) -> usize {
        self.sources.len()
    }

    pub fn record(&self) -> &Record {
        self.record
    }

    pub fn sources(&self) -> &Vec<Source> {
        &self.sources
    }
}

#[derive(Debug)]
pub struct Summary<'a> {
    pub num_of_samples: usize,
    pub num_of_ok_samples: usize,
    pub num_of_err_samples: usize,
    pub min_num_of_records: usize,
    pub max_num_of_records: usize,
    pub record_counts: HashMap<String, RecordCount<'a>>,
    pub failures: Vec<&'a LookupError>,
    pub alerts: Vec<Alert>
}

impl<'a> Summary<'a> {
    pub fn from(responses: &'a [LookupResult<Response>]) -> Self {
        let num_of_samples = responses.len();

        let (responses, failures): (Vec<_>, Vec<_>) =
            responses.into_iter().partition(|x| x.is_ok());
        let successes: Vec<&Response> =
            responses.into_iter().map(|x| x.as_ref().unwrap()).collect();
        let failures: Vec<&LookupError> = failures
            .into_iter()
            .map(|x| x.as_ref().unwrap_err())
            .collect();

        let num_of_ok_samples = successes.len();
        let num_of_err_samples = failures.len();

        let (min_num_of_records, max_num_of_records) = successes
            .iter()
            .map(|x| x.answers.len())
            .fold((::std::usize::MAX, 0), |(mut min, mut max), x| {
                if min > x {
                    min = x
                };
                if max < x {
                    max = x
                };
                (min, max)
            });

        let mut record_counts = HashMap::new();
        for response in &successes {
            for record in &response.answers {
                let key = format!("{:?}-{:?}", record.rr_type(), record.rdata());
                let value = record_counts.entry(key).or_insert( RecordCount{ record, sources: Vec::new() } );
                value.sources.push(response.server.source);
            }
        }

        let alerts = alerts(successes.as_slice());

        Summary {
            num_of_samples,
            num_of_ok_samples,
            num_of_err_samples,
            min_num_of_records,
            max_num_of_records,
            record_counts,
            failures,
            alerts
        }
    }
}

#[derive(Debug)]
pub enum Alert {
    SoaSnDiverge(HashMap<u32, u32>),
}

// TODO: &[&T] is totally weird -- cf. https://users.rust-lang.org/t/solved-function-taking-slice-of-objects-as-well-as-slice-of-references-to-objects/13553/9
fn alerts(responses: &[&Response]) -> Vec<Alert> {
    let mut alerts = Vec::new();
    if let Some(serials) = check_soa_serial_numbers(responses) {
        alerts.push(serials)
    }

    alerts
}

// TODO: &[&T] is totally weird
fn check_soa_serial_numbers(responses: &[&Response]) -> Option<Alert> {
    let mut serial_counts = HashMap::new();
    Itertools::flatten(
        responses
        .iter()
        .map(|r| r.answers
            .iter()
            .map(|a| match *a.rdata() {
                RData::SOA(ref soa) => Some(soa.serial()),
                _ => None
            })
        )
    )
    .filter_map(|x| x)
    .for_each(|key| {
        let value = serial_counts.entry(key).or_insert(0);
        *value += 1;
    });

    if serial_counts.len() > 1 {
        Some(Alert::SoaSnDiverge(serial_counts))
    } else {
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use dns::{ErrorKind as LookupErrorKind, Server, Source};
    use std::net::IpAddr;
    use std::str::FromStr;
    use trust_dns::rr::{domain, RecordType};
    use trust_dns::rr::rdata::SOA;

    #[test]
    fn simple_summary() {
        let records_1: Vec<Record> = vec![
            Record::with(
                domain::Name::from_str("www.example.com").unwrap(),
                RecordType::A,
                100
            ),
            Record::with(
                domain::Name::from_str("www.example.com").unwrap(),
                RecordType::MX,
                99
            ),
        ];
        let response_1 = Response {
            server: Server::udp_from(IpAddr::from([127, 0, 0, 1]), Source::Additional),
            answers: records_1,
        };
        let records_2: Vec<Record> = vec![
            Record::with(
                domain::Name::from_str("www.example.com").unwrap(),
                RecordType::A,
                98
            ),
        ];
        let response_2 = Response {
            server: Server::udp_from(IpAddr::from([127, 0, 0, 2]), Source::Additional),
            answers: records_2,
        };
        let responses: Vec<LookupResult<Response>> =
            vec![
                Ok(response_1),
                Ok(response_2),
                Err(
                    LookupErrorKind::QueryError(1, RecordType::AAAA, IpAddr::from([127, 0, 0, 3]))
                        .into()
                ),
            ];

        let summary = Summary::from(&responses);

        assert_eq!(summary.num_of_samples, 3);
        assert_eq!(summary.num_of_ok_samples, 2);
        assert_eq!(summary.num_of_err_samples, 1);
        assert_eq!(summary.min_num_of_records, 1);
        assert_eq!(summary.max_num_of_records, 2);
        assert_eq!(summary.record_counts.len(), 2);

        let mut record_counts: Vec<_> = summary
            .record_counts
            .values()
            .map(|ref rc| rc.count())
            .collect();
        record_counts.sort();
        assert_eq!(record_counts, vec![1, 2]);

        assert_eq!(summary.failures.len(), 1);
    }

    #[test]
    fn test_alert_for_diverging_soa_serials() {
        let records_1: Vec<Record> = vec![
            Record::from_rdata(
                domain::Name::from_str("www.example.com").unwrap(),
                99,
                RecordType::SOA,
                RData::SOA(
                    SOA::new(
                        domain::Name::from_str("sns.dns.icann.org.").unwrap(),
                        domain::Name::from_str("noc.dns.icann.org.").unwrap(),
                        100,
                        7200,
                        3600,
                        1209600,
                        3600
                    )
                )
            )
        ];
        let response_1 = Response {
            server: Server::udp_from(IpAddr::from([127, 0, 0, 1]), Source::Additional),
            answers: records_1,
        };
        let records_2: Vec<Record> = vec![
            Record::from_rdata(
                domain::Name::from_str("www.example.com").unwrap(),
                99,
                RecordType::SOA,
                RData::SOA(
                    SOA::new(
                        domain::Name::from_str("sns.dns.icann.org.").unwrap(),
                        domain::Name::from_str("noc.dns.icann.org.").unwrap(),
                        200,
                        7200,
                        3600,
                        1209600,
                        3600
                    )
                )
            )];
        let response_2 = Response {
            server: Server::udp_from(IpAddr::from([127, 0, 0, 2]), Source::Additional),
            answers: records_2,
        };
        let responses: Vec<Response> = vec![response_1, response_2, ];

        let alerts = alerts(&responses.iter().collect::<Vec<_>>());

        assert_eq!(alerts.len(), 1);
        let &Alert::SoaSnDiverge(ref soa_serials) = alerts.first().unwrap();
        let mut serials = soa_serials.keys().collect::<Vec<_>>();
        serials.sort();
        assert_eq!(serials, vec![&100, &200]);
        let mut counts = soa_serials.values().collect::<Vec<_>>();
        counts.sort();
        assert_eq!(counts, vec![&1, &1]);
    }
}
