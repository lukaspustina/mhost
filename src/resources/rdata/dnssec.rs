// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use serde::Serialize;

/// Wrapper for DNSSEC record data.
///
/// Since mhost consolidates all DNSSEC record types (DNSKEY, DS, RRSIG, NSEC, etc.)
/// into a single RecordType::DNSSEC variant, this struct provides a uniform representation
/// with the sub-type name and a human-readable description of the data.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct DNSSEC {
    sub_type: String,
    description: String,
}

impl DNSSEC {
    pub fn new(sub_type: String, description: String) -> DNSSEC {
        DNSSEC { sub_type, description }
    }

    /// The specific DNSSEC record sub-type (e.g., "DNSKEY", "DS", "RRSIG", "NSEC").
    pub fn sub_type(&self) -> &str {
        &self.sub_type
    }

    /// Human-readable description of the DNSSEC record data.
    pub fn description(&self) -> &str {
        &self.description
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dnssec_new_and_accessors() {
        let dnssec = DNSSEC::new("DNSKEY".to_string(), "256 3 8 AwEAAb...".to_string());
        assert_eq!(dnssec.sub_type(), "DNSKEY");
        assert_eq!(dnssec.description(), "256 3 8 AwEAAb...");
    }

    #[test]
    fn dnssec_various_sub_types() {
        for sub_type in &["DS", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM"] {
            let dnssec = DNSSEC::new(sub_type.to_string(), "test data".to_string());
            assert_eq!(dnssec.sub_type(), *sub_type);
        }
    }
}
