// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Terminal-styled `Display` implementations for statistics types.
//!
//! The data structs and aggregation logic live in the core library
//! (`crate::statistics`). The `Display` impls are here because they depend
//! on `yansi` for coloured terminal output, which is an app-layer concern.

use std::collections::BTreeMap;
use std::fmt;

use yansi::Paint;

use crate::statistics::lookups::LookupsStats;
#[cfg(feature = "services")]
use crate::statistics::server_lists::DownloadResponsesStats;
#[cfg(feature = "services")]
use crate::statistics::whois::WhoisStats;
use crate::RecordType;

mod styles {
    use yansi::{Color, Style};

    pub static NORMAL: Style = Style::new();
    pub static BOLD: Style = Style::new().fg(Color::White).bold();
    pub static GOOD: Style = Style::new().fg(Color::Green);
    pub static WARN: Style = Style::new().fg(Color::Yellow);
    pub static ERR: Style = Style::new().fg(Color::Red);
}

impl fmt::Display for LookupsStats<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fn fmt_errors(errors: usize, timeouts: usize, refuses: usize, servfails: usize) -> String {
            if errors == 0 {
                return "0 Err".to_string();
            }
            let others = errors - timeouts - refuses - servfails;
            format!(
                "{num_err} Err [{num_to} TO, {num_qr} QR, {num_sf} SF, {num_others} O]",
                num_err = if errors > 0 {
                    errors.paint(styles::ERR)
                } else {
                    errors.paint(styles::NORMAL)
                },
                num_to = if timeouts > 0 {
                    timeouts.paint(styles::ERR)
                } else {
                    timeouts.paint(styles::NORMAL)
                },
                num_qr = if refuses > 0 {
                    refuses.paint(styles::ERR)
                } else {
                    refuses.paint(styles::NORMAL)
                },
                num_sf = if servfails > 0 {
                    servfails.paint(styles::ERR)
                } else {
                    servfails.paint(styles::NORMAL)
                },
                num_others = if others > 0 {
                    others.paint(styles::ERR)
                } else {
                    others.paint(styles::NORMAL)
                },
            )
        }

        let rr_types = rr_types_as_str(&self.rr_type_counts);
        let num_rr = count_rrs(&self.rr_type_counts);
        let str = format!("{num_resp} responses with {num_rr} RR [{rr_types}], {num_nx} Nx, {errs} in (min {min_time}, max {max_time}) ms from {num_srvs} server{servers}",
                          num_resp = self.responses.paint(styles::BOLD),
                          num_rr = num_rr.paint(styles::GOOD),
                          rr_types = rr_types,
                          num_nx = self.nxdomains.paint(styles::WARN),
                          errs = fmt_errors(self.total_errors, self.timeout_errors, self.refuse_errors, self.servfail_errors),
                          min_time = self.response_time_summary.min.map(|x| x.to_string()).unwrap_or_else(|| "-".to_string()),
                          max_time = self.response_time_summary.max.map(|x| x.to_string()).unwrap_or_else(|| "-".to_string()),
                          num_srvs = self.responding_servers.paint(styles::BOLD),
                          servers = if self.responding_servers == 1 { "" } else { "s" },
        );
        f.write_str(&str)
    }
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

#[cfg(feature = "services")]
impl fmt::Display for WhoisStats<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fn fmt_errors(errors: usize) -> String {
            if errors == 0 {
                "0 Err".to_string()
            } else {
                format!("{} Err", errors.paint(styles::ERR))
            }
        }

        let str = format!(
            "{num_resp} responses [GL {num_gl}, NI {num_ni}, WI {num_wi}], {errs}",
            num_resp = self.responses.paint(styles::BOLD),
            num_gl = self.geo_locations,
            num_ni = self.network_infos,
            num_wi = self.whois,
            errs = fmt_errors(self.errors),
        );
        f.write_str(&str)
    }
}

#[cfg(feature = "services")]
impl fmt::Display for DownloadResponsesStats<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fn fmt_errors(errors: usize) -> String {
            if errors == 0 {
                "0 Err".to_string()
            } else {
                format!("{} Err", errors.paint(styles::ERR))
            }
        }

        let str = format!(
            "{num_servers} name servers, {errs}",
            num_servers = self.nameserver_configs.paint(styles::BOLD),
            errs = fmt_errors(self.errors),
        );
        f.write_str(&str)
    }
}
