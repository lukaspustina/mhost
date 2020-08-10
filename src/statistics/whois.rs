use std::fmt;
use std::marker::PhantomData;

use crate::services::ripe_stats::RipeStatsResponses;

use super::*;

#[derive(Debug)]
pub struct WhoisStats<'a> {
    pub responses: usize,
    pub geo_locations: usize,
    pub network_infos: usize,
    pub whois: usize,
    pub errors: usize,
    // This is used to please the borrow checker as we currently don't use a borrowed value with lifetime 'a
    phantom: PhantomData<&'a usize>,
}

impl<'a> fmt::Display for WhoisStats<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fn fmt_errors(errors: usize) -> String {
            if errors == 0 {
                "0 Err".to_string()
            } else {
                format!("{} Err", styles::ERR.paint(errors))
            }
        }

        let str = format!(
            "{num_resp} responses [GL {num_gl}, NI {num_ni}, WI {num_wi}], {errs}",
            num_resp = styles::BOLD.paint(self.responses),
            num_gl = self.geo_locations,
            num_ni = self.network_infos,
            num_wi = self.whois,
            errs = fmt_errors(self.errors),
        );
        f.write_str(&str)
    }
}

impl<'a> Statistics<'a> for RipeStatsResponses {
    type StatsOut = WhoisStats<'a>;

    fn statistics(&'a self) -> Self::StatsOut {
        WhoisStats {
            responses: self.iter().count(),
            geo_locations: self.geo_location().count(),
            network_infos: self.network_info().count(),
            whois: self.whois().count(),
            errors: self.err().count(),
            phantom: PhantomData,
        }
    }
}
