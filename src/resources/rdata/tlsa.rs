// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use serde::Serialize;
use std::fmt;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
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

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Serialize)]
pub enum CertUsage {
    /// CA constraint (0)
    PkixTa,
    /// Service certificate constraint (1)
    PkixEe,
    /// Trust anchor assertion (2)
    DaneTa,
    /// Domain-issued certificate (3)
    DaneEe,
    Unassigned(u8),
    /// Private use (255)
    Private,
}

impl fmt::Display for CertUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertUsage::PkixTa => write!(f, "PKIX-TA"),
            CertUsage::PkixEe => write!(f, "PKIX-EE"),
            CertUsage::DaneTa => write!(f, "DANE-TA"),
            CertUsage::DaneEe => write!(f, "DANE-EE"),
            CertUsage::Unassigned(v) => write!(f, "Unassigned({})", v),
            CertUsage::Private => write!(f, "Private"),
        }
    }
}

impl From<u8> for CertUsage {
    fn from(v: u8) -> Self {
        match v {
            0 => CertUsage::PkixTa,
            1 => CertUsage::PkixEe,
            2 => CertUsage::DaneTa,
            3 => CertUsage::DaneEe,
            255 => CertUsage::Private,
            v => CertUsage::Unassigned(v),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Serialize)]
pub enum Selector {
    /// Full certificate (0)
    Full,
    /// SubjectPublicKeyInfo (1)
    Spki,
    Unassigned(u8),
    /// Private use (255)
    Private,
}

impl fmt::Display for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Selector::Full => write!(f, "Full"),
            Selector::Spki => write!(f, "SPKI"),
            Selector::Unassigned(v) => write!(f, "Unassigned({})", v),
            Selector::Private => write!(f, "Private"),
        }
    }
}

impl From<u8> for Selector {
    fn from(v: u8) -> Self {
        match v {
            0 => Selector::Full,
            1 => Selector::Spki,
            255 => Selector::Private,
            v => Selector::Unassigned(v),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Serialize)]
pub enum Matching {
    /// Exact match on selected content (0)
    Raw,
    /// SHA-256 hash of selected content (1)
    Sha256,
    /// SHA-512 hash of selected content (2)
    Sha512,
    Unassigned(u8),
    /// Private use (255)
    Private,
}

impl fmt::Display for Matching {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Matching::Raw => write!(f, "Raw"),
            Matching::Sha256 => write!(f, "SHA-256"),
            Matching::Sha512 => write!(f, "SHA-512"),
            Matching::Unassigned(v) => write!(f, "Unassigned({})", v),
            Matching::Private => write!(f, "Private"),
        }
    }
}

impl From<u8> for Matching {
    fn from(v: u8) -> Self {
        match v {
            0 => Matching::Raw,
            1 => Matching::Sha256,
            2 => Matching::Sha512,
            255 => Matching::Private,
            v => Matching::Unassigned(v),
        }
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
