use std::collections::HashSet;

use crate::lookup::LookupResult;
use crate::lookup::Lookup;

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
    pub responding_servers: usize,
    pub response_time_summary: Summary,
}

impl Statistics for Vec<Lookup> {
    type StatsOut = LookupsStats;

    fn statistics(&self) -> Self::StatsOut {
        let responding_servers = count_responding_servers(&self);
        let (responses, nxdomains, timeouts, errors) = count_result_types(&self);
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

