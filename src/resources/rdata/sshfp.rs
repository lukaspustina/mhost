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
pub struct SSHFP {
    algorithm: Algorithm,
    fingerprint_type: FingerprintType,
    fingerprint: Vec<u8>,
}

impl SSHFP {
    pub fn new(algorithm: Algorithm, fingerprint_type: FingerprintType, fingerprint: Vec<u8>) -> SSHFP {
        SSHFP {
            algorithm,
            fingerprint_type,
            fingerprint,
        }
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub fn fingerprint_type(&self) -> FingerprintType {
        self.fingerprint_type
    }

    pub fn fingerprint(&self) -> &[u8] {
        &self.fingerprint
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Serialize)]
#[allow(clippy::upper_case_acronyms)]
pub enum Algorithm {
    Reserved,
    RSA,
    DSA,
    ECDSA,
    Ed25519,
    Ed448,
    Unassigned(u8),
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Algorithm::Reserved => write!(f, "Reserved"),
            Algorithm::RSA => write!(f, "RSA"),
            Algorithm::DSA => write!(f, "DSA"),
            Algorithm::ECDSA => write!(f, "ECDSA"),
            Algorithm::Ed25519 => write!(f, "Ed25519"),
            Algorithm::Ed448 => write!(f, "Ed448"),
            Algorithm::Unassigned(v) => write!(f, "Unassigned({})", v),
        }
    }
}

impl From<u8> for Algorithm {
    fn from(v: u8) -> Self {
        match v {
            0 => Algorithm::Reserved,
            1 => Algorithm::RSA,
            2 => Algorithm::DSA,
            3 => Algorithm::ECDSA,
            4 => Algorithm::Ed25519,
            6 => Algorithm::Ed448,
            v => Algorithm::Unassigned(v),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Serialize)]
pub enum FingerprintType {
    Reserved,
    SHA1,
    SHA256,
    Unassigned(u8),
}

impl fmt::Display for FingerprintType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FingerprintType::Reserved => write!(f, "Reserved"),
            FingerprintType::SHA1 => write!(f, "SHA-1"),
            FingerprintType::SHA256 => write!(f, "SHA-256"),
            FingerprintType::Unassigned(v) => write!(f, "Unassigned({})", v),
        }
    }
}

impl From<u8> for FingerprintType {
    fn from(v: u8) -> Self {
        match v {
            0 => FingerprintType::Reserved,
            1 => FingerprintType::SHA1,
            2 => FingerprintType::SHA256,
            v => FingerprintType::Unassigned(v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sshfp_new_and_accessors() {
        let fp = vec![0xaa, 0xbb, 0xcc];
        let sshfp = SSHFP::new(Algorithm::RSA, FingerprintType::SHA256, fp.clone());
        assert_eq!(sshfp.algorithm(), Algorithm::RSA);
        assert_eq!(sshfp.fingerprint_type(), FingerprintType::SHA256);
        assert_eq!(sshfp.fingerprint(), &fp[..]);
    }

    #[test]
    fn algorithm_from_u8_known_values() {
        assert_eq!(Algorithm::from(0), Algorithm::Reserved);
        assert_eq!(Algorithm::from(1), Algorithm::RSA);
        assert_eq!(Algorithm::from(2), Algorithm::DSA);
        assert_eq!(Algorithm::from(3), Algorithm::ECDSA);
        assert_eq!(Algorithm::from(4), Algorithm::Ed25519);
        assert_eq!(Algorithm::from(6), Algorithm::Ed448);
    }

    #[test]
    fn algorithm_from_u8_unassigned() {
        assert_eq!(Algorithm::from(5), Algorithm::Unassigned(5));
        assert_eq!(Algorithm::from(7), Algorithm::Unassigned(7));
        assert_eq!(Algorithm::from(255), Algorithm::Unassigned(255));
    }

    #[test]
    fn algorithm_display() {
        assert_eq!(Algorithm::Reserved.to_string(), "Reserved");
        assert_eq!(Algorithm::RSA.to_string(), "RSA");
        assert_eq!(Algorithm::DSA.to_string(), "DSA");
        assert_eq!(Algorithm::ECDSA.to_string(), "ECDSA");
        assert_eq!(Algorithm::Ed25519.to_string(), "Ed25519");
        assert_eq!(Algorithm::Ed448.to_string(), "Ed448");
        assert_eq!(Algorithm::Unassigned(42).to_string(), "Unassigned(42)");
    }

    #[test]
    fn fingerprint_type_from_u8_known_values() {
        assert_eq!(FingerprintType::from(0), FingerprintType::Reserved);
        assert_eq!(FingerprintType::from(1), FingerprintType::SHA1);
        assert_eq!(FingerprintType::from(2), FingerprintType::SHA256);
    }

    #[test]
    fn fingerprint_type_from_u8_unassigned() {
        assert_eq!(FingerprintType::from(3), FingerprintType::Unassigned(3));
        assert_eq!(FingerprintType::from(255), FingerprintType::Unassigned(255));
    }

    #[test]
    fn fingerprint_type_display() {
        assert_eq!(FingerprintType::Reserved.to_string(), "Reserved");
        assert_eq!(FingerprintType::SHA1.to_string(), "SHA-1");
        assert_eq!(FingerprintType::SHA256.to_string(), "SHA-256");
        assert_eq!(FingerprintType::Unassigned(10).to_string(), "Unassigned(10)");
    }
}

#[doc(hidden)]
impl From<hickory_resolver::proto::rr::rdata::SSHFP> for SSHFP {
    fn from(sshfp: hickory_resolver::proto::rr::rdata::SSHFP) -> Self {
        let algo_u8: u8 = sshfp.algorithm().into();
        let fp_type_u8: u8 = sshfp.fingerprint_type().into();

        SSHFP {
            algorithm: algo_u8.into(),
            fingerprint_type: fp_type_u8.into(),
            fingerprint: sshfp.fingerprint().to_vec(),
        }
    }
}
