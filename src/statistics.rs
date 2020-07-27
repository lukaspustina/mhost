use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::marker::PhantomData;

use crate::resolver::lookup::LookupResult;
use crate::resolver::Lookups;
use crate::RecordType;

pub trait Statistics<'a> {
    type StatsOut;

    fn statistics(&'a self) -> Self::StatsOut;
}

#[derive(Debug)]
pub struct LookupsStats<'a> {
    pub responses: usize,
    pub nxdomains: usize,
    pub timeouts: usize,
    pub errors: usize,
    pub rr_type_counts: BTreeMap<RecordType, usize>,
    pub responding_servers: usize,
    pub response_time_summary: Summary<u128>,
    // This is used to please the borrow checker as we currently don't use a borrowed value with lifetime 'a
    phantom: PhantomData<&'a usize>,
}

impl<'a> Statistics<'a> for Lookups {
    type StatsOut = LookupsStats<'a>;

    fn statistics(&'a self) -> Self::StatsOut {
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
            phantom: PhantomData,
        }
    }
}

impl<'a> fmt::Display for LookupsStats<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let rr_types = rr_types_as_str(&self.rr_type_counts);
        let num_rr = count_rrs(&self.rr_type_counts);
        let str = format!("{num_resp} responses with {num_rr} RR [{rr_types}], {num_nx} Nx, {num_to} TO, {num_err} Err in (min {min_time}, max {max_time}) ms from {num_srvs} server{servers}",
                          num_resp = styles::BOLD.paint(self.responses),
                          num_rr = styles::GOOD.paint(num_rr),
                          rr_types = rr_types,
                          num_nx = styles::WARN.paint(self.nxdomains),
                          num_to = if self.timeouts > 0 {styles::ERR.paint(self.timeouts)} else {styles::NORMAL.paint(self.timeouts)},
                          num_err = if self.errors > 0 {styles::ERR.paint(self.errors)} else {styles::NORMAL.paint(self.errors)},
                          min_time = self.response_time_summary.min.map(|x| x.to_string()).unwrap_or_else(|| "-".to_string()),
                          max_time = self.response_time_summary.max.map(|x| x.to_string()).unwrap_or_else(|| "-".to_string()),
                          num_srvs = styles::BOLD.paint(self.responding_servers),
                          servers = if self.responding_servers == 1 { "" } else { "s" },
        );
        f.write_str(&str)
    }
}

mod styles {
    use lazy_static::lazy_static;
    use yansi::{Color, Style};

    lazy_static! {
        pub static ref NORMAL: Style = Style::default();
        pub static ref BOLD: Style = Style::new(Color::White).bold();
        pub static ref GOOD: Style = Style::new(Color::Green);
        pub static ref WARN: Style = Style::new(Color::Yellow);
        pub static ref ERR: Style = Style::new(Color::Red);
    }
}

#[derive(Debug)]
pub struct Summary<T: Ord + Clone> {
    pub min: Option<T>,
    pub max: Option<T>,
}

impl<T: Ord + Clone> Summary<T> {
    pub fn summary(values: &[T]) -> Summary<T> {
        let min = values.iter().min().cloned();
        let max = values.iter().max().cloned();

        Summary { min, max }
    }
}

fn count_rr_types(lookups: &Lookups) -> BTreeMap<RecordType, usize> {
    let mut type_counts = BTreeMap::new();

    for l in lookups.iter() {
        if let Some(response) = l.result().response() {
            for r in response.records() {
                let type_count = type_counts.entry(r.record_type()).or_insert(0);
                *type_count += 1;
            }
        }
    }

    type_counts
}

fn count_responding_servers(lookups: &Lookups) -> usize {
    let server_set: HashSet<_> = lookups
        .iter()
        .filter(|x| x.result().is_response())
        .map(|x| x.name_server().to_string())
        .collect();

    server_set.len()
}

fn count_result_types(lookups: &Lookups) -> (usize, usize, usize, usize) {
    let mut responses: usize = 0;
    let mut nxdomains: usize = 0;
    let mut timeouts: usize = 0;
    let mut errors: usize = 0;

    for l in lookups.iter() {
        match l.result() {
            LookupResult::Response { .. } => responses += 1,
            LookupResult::NxDomain { .. } => nxdomains += 1,
            LookupResult::Timeout => timeouts += 1,
            LookupResult::Error { .. } => errors += 1,
        }
    }

    (responses, nxdomains, timeouts, errors)
}

fn rr_types_as_str(rr_type_counts: &BTreeMap<RecordType, usize>) -> String {
    rr_type_counts
        .iter()
        .map(|x| format!("{} {}", x.1, x.0))
        .collect::<Vec<_>>()
        .as_slice()
        .join(", ")
}

fn count_rrs(rr_type_counts: &BTreeMap<RecordType, usize>) -> usize {
    rr_type_counts.values().sum()
}
