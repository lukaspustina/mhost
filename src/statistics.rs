use std::collections::{BTreeMap, HashSet};

use crate::lookup::Lookup;
use crate::lookup::LookupResult;
use crate::RecordType;

pub trait Statistics {
    type StatsOut;

    fn statistics(&self) -> Self::StatsOut;
}

#[derive(Debug)]
pub struct LookupsStats {
    pub responses: usize,
    pub nxdomains: usize,
    pub timeouts: usize,
    pub errors: usize,
    pub rr_type_counts: BTreeMap<RecordType, usize>,
    pub responding_servers: usize,
    pub response_time_summary: Summary,
}

impl Statistics for Vec<Lookup> {
    type StatsOut = LookupsStats;

    fn statistics(&self) -> Self::StatsOut {
        let (responses, nxdomains, timeouts, errors) = count_result_types(&self);
        let rr_type_counts = count_rr_types(&self);
        let responding_servers = count_responding_servers(&self);
        let response_times: Vec<_> = self
            .iter()
            .map(|x| x.result().response())
            .flatten()
            .map(|x| x.response_time().as_millis())
            .collect();
        let response_time_summary = Summary::summary(response_times.as_slice());

        LookupsStats {
            responses,
            nxdomains,
            timeouts,
            errors,
            rr_type_counts,
            responding_servers,
            response_time_summary,
        }
    }
}

#[derive(Debug)]
pub struct Summary {
    pub min: Option<u128>,
    pub max: Option<u128>,
}

impl Summary {
    pub fn summary(values: &[u128]) -> Summary {
        let min = values.iter().min().cloned();
        let max = values.iter().max().cloned();

        Summary { min, max }
    }
}

fn count_rr_types(lookups: &[Lookup]) -> BTreeMap<RecordType, usize> {
    let mut type_counts = BTreeMap::new();

    for l in lookups {
        if let Some(response) = l.result().response() {
            for r in response.records() {
                let type_count = type_counts.entry(r.rr_type).or_insert(0);
                *type_count += 1;
            }
        }
    }

    type_counts
}

fn count_responding_servers(lookups: &[Lookup]) -> usize {
    let server_set: HashSet<_> = lookups.iter().map(|x| x.name_server().to_string()).collect();

    server_set.len()
}

fn count_result_types(lookups: &[Lookup]) -> (usize, usize, usize, usize) {
    let mut responses: usize = 0;
    let mut nxdomains: usize = 0;
    let mut timeouts: usize = 0;
    let mut errors: usize = 0;

    for l in lookups {
        match l.result() {
            LookupResult::Response { .. } => responses += 1,
            LookupResult::NxDomain { .. } => nxdomains += 1,
            LookupResult::Timeout => timeouts += 1,
            LookupResult::Error { .. } => errors += 1,
        }
    }

    (responses, nxdomains, timeouts, errors)
}
