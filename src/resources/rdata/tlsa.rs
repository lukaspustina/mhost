// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct TLSA {
    cert_usage: CertUsage,
    selector: Selector,
    matching: Matching,
    cert_data: Vec<u8>,
}

impl TLSA {
    pub fn new(cert_usage: CertUsage, selector: Selector, matching: Matching, cert_data: Vec<u8>) -> TLSA {
        TLSA {
            cert_usage,
            selector,
            matching,
            cert_data,
        }
    }

    pub fn cert_usage(&self) -> CertUsage {
        self.cert_usage
    }

    pub fn selector(&self) -> Selector {
        self.selector
    }

    pub fn matching(&self) -> Matching {
        self.matching
    }

    pub fn cert_data(&self) -> &[u8] {
        &self.cert_data
    }
}

iana_enum! {
    pub enum CertUsage {
        /// CA constraint (0)
        PkixTa = 0 => "PKIX-TA",
        /// Service certificate constraint (1)
        PkixEe = 1 => "PKIX-EE",
        /// Trust anchor assertion (2)
        DaneTa = 2 => "DANE-TA",
        /// Domain-issued certificate (3)
        DaneEe = 3 => "DANE-EE",
        /// Private use (255)
        Private = 255 => "Private",
    }
}

iana_enum! {
    pub enum Selector {
        /// Full certificate (0)
        Full = 0 => "Full",
        /// SubjectPublicKeyInfo (1)
        Spki = 1 => "SPKI",
        /// Private use (255)
        Private = 255 => "Private",
    }
}

iana_enum! {
    pub enum Matching {
        /// Exact match on selected content (0)
        Raw = 0 => "Raw",
        /// SHA-256 hash of selected content (1)
        Sha256 = 1 => "SHA-256",
        /// SHA-512 hash of selected content (2)
        Sha512 = 2 => "SHA-512",
        /// Private use (255)
        Private = 255 => "Private",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlsa_new_and_accessors() {
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        let tlsa = TLSA::new(CertUsage::DaneEe, Selector::Spki, Matching::Sha256, data.clone());
        assert_eq!(tlsa.cert_usage(), CertUsage::DaneEe);
        assert_eq!(tlsa.selector(), Selector::Spki);
        assert_eq!(tlsa.matching(), Matching::Sha256);
        assert_eq!(tlsa.cert_data(), &data[..]);
    }

    #[test]
    fn cert_usage_from_u8() {
        assert_eq!(CertUsage::from(0), CertUsage::PkixTa);
        assert_eq!(CertUsage::from(1), CertUsage::PkixEe);
        assert_eq!(CertUsage::from(2), CertUsage::DaneTa);
        assert_eq!(CertUsage::from(3), CertUsage::DaneEe);
        assert_eq!(CertUsage::from(255), CertUsage::Private);
        assert_eq!(CertUsage::from(100), CertUsage::Unassigned(100));
    }

    #[test]
    fn cert_usage_display() {
        assert_eq!(CertUsage::PkixTa.to_string(), "PKIX-TA");
        assert_eq!(CertUsage::PkixEe.to_string(), "PKIX-EE");
        assert_eq!(CertUsage::DaneTa.to_string(), "DANE-TA");
        assert_eq!(CertUsage::DaneEe.to_string(), "DANE-EE");
        assert_eq!(CertUsage::Private.to_string(), "Private");
        assert_eq!(CertUsage::Unassigned(50).to_string(), "Unassigned(50)");
    }

    #[test]
    fn selector_from_u8() {
        assert_eq!(Selector::from(0), Selector::Full);
        assert_eq!(Selector::from(1), Selector::Spki);
        assert_eq!(Selector::from(255), Selector::Private);
        assert_eq!(Selector::from(2), Selector::Unassigned(2));
    }

    #[test]
    fn selector_display() {
        assert_eq!(Selector::Full.to_string(), "Full");
        assert_eq!(Selector::Spki.to_string(), "SPKI");
        assert_eq!(Selector::Private.to_string(), "Private");
        assert_eq!(Selector::Unassigned(10).to_string(), "Unassigned(10)");
    }

    #[test]
    fn matching_from_u8() {
        assert_eq!(Matching::from(0), Matching::Raw);
        assert_eq!(Matching::from(1), Matching::Sha256);
        assert_eq!(Matching::from(2), Matching::Sha512);
        assert_eq!(Matching::from(255), Matching::Private);
        assert_eq!(Matching::from(100), Matching::Unassigned(100));
    }

    #[test]
    fn matching_display() {
        assert_eq!(Matching::Raw.to_string(), "Raw");
        assert_eq!(Matching::Sha256.to_string(), "SHA-256");
        assert_eq!(Matching::Sha512.to_string(), "SHA-512");
        assert_eq!(Matching::Private.to_string(), "Private");
        assert_eq!(Matching::Unassigned(7).to_string(), "Unassigned(7)");
    }
}

#[doc(hidden)]
impl From<hickory_resolver::proto::rr::rdata::TLSA> for TLSA {
    fn from(tlsa: hickory_resolver::proto::rr::rdata::TLSA) -> Self {
        let cert_usage_u8: u8 = tlsa.cert_usage().into();
        let selector_u8: u8 = tlsa.selector().into();
        let matching_u8: u8 = tlsa.matching().into();

        TLSA {
            cert_usage: cert_usage_u8.into(),
            selector: selector_u8.into(),
            matching: matching_u8.into(),
            cert_data: tlsa.cert_data().to_vec(),
        }
    }
}
