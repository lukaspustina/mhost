use crate::app::common::lints::{self, CheckResult};
use crate::resolver::lookup::Uniquify;
use crate::resolver::Lookups;
use crate::resources::rdata::TXT;

#[derive(Clone)]
pub struct LintSection {
    pub name: &'static str,
    pub results: Vec<CheckResult>,
}

pub fn run_lints(lookups: &Lookups) -> Vec<LintSection> {
    // DMARC: extract DMARC TXT records from lookups (mdive already queried _dmarc.<domain>)
    let dmarc_txts: Vec<String> = lookups
        .txt()
        .unique()
        .iter()
        .map(TXT::as_string)
        .filter(|s| lints::is_dmarc(s))
        .collect();

    let sections = vec![
        LintSection {
            name: "CNAME",
            results: lints::check_cname_apex(lookups),
        },
        LintSection {
            name: "NS",
            results: lints::check_ns_count(lookups),
        },
        LintSection {
            name: "MX",
            results: lints::check_mx_sync(lookups),
        },
        LintSection {
            name: "HTTPS/SVCB",
            results: lints::check_https_svcb_mode(lookups),
        },
        LintSection {
            name: "SPF",
            results: lints::check_spf(lookups),
        },
        LintSection {
            name: "DMARC",
            results: lints::check_dmarc_records(&dmarc_txts),
        },
        LintSection {
            name: "CAA",
            results: lints::check_caa(lookups),
        },
        LintSection {
            name: "TTL",
            results: lints::check_ttl(lookups),
        },
        LintSection {
            name: "DNSSEC",
            results: lints::check_dnssec(lookups),
        },
    ];

    // Keep sections that have meaningful results
    sections
        .into_iter()
        .filter(|s| !s.results.is_empty() && !s.results.iter().all(|r| matches!(r, CheckResult::NotFound())))
        .collect()
}
