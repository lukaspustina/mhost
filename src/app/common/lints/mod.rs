// Re-export all lints from the core library for backward compatibility.
// The canonical location is now crate::lints.
pub use crate::lints::*;

// Re-export submodules so `crate::app::common::lints::cnames::classify_chain_depth` etc. still resolve.
pub use crate::lints::caa;
pub use crate::lints::cnames;
pub use crate::lints::dmarc;
pub use crate::lints::dnssec_lint;
pub use crate::lints::https_svcb;
pub use crate::lints::mx;
pub use crate::lints::ns;
pub use crate::lints::spf;
pub use crate::lints::ttl;
