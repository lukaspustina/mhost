// TODO: deny missing docs
#![allow(missing_docs)]

use lookup::{Response, Result as LookupResult, Error as LookupError};

use std::collections::HashMap;
use trust_dns::rr::Record;

pub struct Statistics<'a> {
    pub num_of_samples: usize,
    pub num_of_ok_samples: usize,
    pub num_of_err_samples: usize,
    pub min_num_of_records: usize,
    pub max_num_of_records: usize,
    pub record_counts: HashMap<String, (&'a Record, u16)>,
    pub failures: Vec<&'a LookupError>,
}

impl<'a> Statistics<'a> {
    pub fn from(responses: &'a [LookupResult<Response>]) -> Self {
        let num_of_samples = responses.len();

        let (responses, failures): (Vec<_>, Vec<_>) =
            responses.into_iter().partition(|x| x.is_ok());
        let responses: Vec<&Response> =
            responses.into_iter().map(|x| x.as_ref().unwrap()).collect();
        let failures: Vec<&LookupError> = failures
            .into_iter()
            .map(|x| x.as_ref().unwrap_err())
            .collect();

        let num_of_ok_samples = responses.len();
        let num_of_err_samples = failures.len();

        let (min_num_of_records, max_num_of_records) = responses
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
        for response in &responses {
            for rr in &response.answers {
                let key = format!("{:?}-{:?}", rr.rr_type(), rr.rdata());
                let value = record_counts.entry(key).or_insert((rr, 0u16));
                value.1 += 1
            }
        }

        Statistics {
            num_of_samples,
            num_of_ok_samples,
            num_of_err_samples,
            min_num_of_records,
            max_num_of_records,
            record_counts,
            failures,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use lookup::ErrorKind as LookupErrorKind;
    use std::net::IpAddr;
    use std::str::FromStr;
    use trust_dns::rr::{domain, RecordType};

    #[test]
    fn simple_statistics() {
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
            server: IpAddr::from([127, 0, 0, 1]),
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
            server: IpAddr::from([127, 0, 0, 2]),
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

        let statistics = Statistics::from(&responses);

        assert_eq!(statistics.num_of_samples, 3);
        assert_eq!(statistics.num_of_ok_samples, 2);
        assert_eq!(statistics.num_of_err_samples, 1);
        assert_eq!(statistics.min_num_of_records, 1);
        assert_eq!(statistics.max_num_of_records, 2);
        assert_eq!(statistics.record_counts.len(), 2);

        let mut record_counts: Vec<_> = statistics
            .record_counts
            .values()
            .map(|&(_, count)| count)
            .collect();
        record_counts.sort();
        assert_eq!(record_counts, vec![1, 2]);

        assert_eq!(statistics.failures.len(), 1);
    }
}
