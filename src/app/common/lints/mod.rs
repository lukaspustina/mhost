use serde::Serialize;

pub mod caa;
pub mod cnames;
pub mod dmarc;
pub mod dnssec_lint;
pub mod https_svcb;
pub mod mx;
pub mod ns;
pub mod spf;
pub mod ttl;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum CheckResult {
    NotFound(),
    Ok(String),
    Warning(String),
    Failed(String),
}

impl CheckResult {
    pub fn is_warning(&self) -> bool {
        matches!(self, CheckResult::Warning(_))
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, CheckResult::Failed(_))
    }
}

// Re-export shared lint functions
pub use caa::check_caa;
pub use cnames::check_cname_apex;
pub use dmarc::{check_dmarc_records, is_dmarc};
pub use dnssec_lint::check_dnssec;
pub use https_svcb::check_https_svcb_mode;
pub use mx::check_mx_sync;
pub use ns::check_ns_count;
pub use spf::check_spf;
pub use ttl::check_ttl;
