//! Resources
//!
//! This is mostly a copy of the trust-dns' types in order to gain more control. Please see [Trust-DNS RR module](http://trust-dns.org/target/doc/trust_dns/rr/index.html)
//!

pub mod rdata;
pub use rdata::RData;
pub mod record_type;
pub use record_type::RecordType;
pub mod record;
pub use record::Record;
