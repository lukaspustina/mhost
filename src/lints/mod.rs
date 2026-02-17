// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Pure DNS lint checks that analyse [`Lookups`] results for common misconfigurations.
//!
//! Each submodule targets a specific DNS record type or practice (CAA, CNAME, DMARC,
//! DNSSEC, HTTPS/SVCB, MX, NS, SPF, TTL). The lint functions are synchronous, pure
//! functions with no network or app-layer dependencies, making them suitable for both
//! library consumers and application code.
//!
//! # Key types
//!
//! - [`CheckResult`] — outcome of an individual lint check (Ok / Warning / Failed / NotFound).
//!
//! # Example
//!
//! ```no_run
//! use mhost::lints::{check_spf, CheckResult};
//! # use mhost::resolver::Lookups;
//! # fn example(lookups: &Lookups) {
//! let results = check_spf(lookups);
//! for r in &results {
//!     if r.is_failed() {
//!         eprintln!("SPF lint failure: {:?}", r);
//!     }
//! }
//! # }
//! ```
//!
//! [`Lookups`]: crate::resolver::Lookups

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

/// Outcome of an individual lint check.
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
