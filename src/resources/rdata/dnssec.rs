// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use serde::Serialize;
use std::fmt;

use super::Name;

iana_enum! {
    /// DNSSEC algorithm numbers per IANA registry.
    pub enum DnssecAlgorithm {
        RsaMd5 = 1 => "RSA/MD5",
        Dsa = 3 => "DSA",
        RsaSha1 = 5 => "RSA/SHA-1",
        RsaSha1Nsec3Sha1 = 7 => "RSA/SHA-1 NSEC3",
        RsaSha256 = 8 => "RSA/SHA-256",
        RsaSha512 = 10 => "RSA/SHA-512",
        EcdsaP256Sha256 = 13 => "ECDSA P-256/SHA-256",
        EcdsaP384Sha384 = 14 => "ECDSA P-384/SHA-384",
        Ed25519 = 15 => "Ed25519",
        Ed448 = 16 => "Ed448",
    }
}

iana_enum! {
    /// DS digest type per IANA registry.
    pub enum DigestType {
        Sha1 = 1 => "SHA-1",
        Sha256 = 2 => "SHA-256",
        Sha384 = 4 => "SHA-384",
    }
}

/// DNSKEY record data: public key used for DNSSEC validation.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct DNSKEY {
    flags: u16,
    protocol: u8,
    algorithm: DnssecAlgorithm,
    public_key: String,
    key_tag: Option<u16>,
    is_zone_key: bool,
    is_secure_entry_point: bool,
    is_revoked: bool,
}

impl DNSKEY {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        flags: u16,
        protocol: u8,
        algorithm: DnssecAlgorithm,
        public_key: String,
        key_tag: Option<u16>,
        is_zone_key: bool,
        is_secure_entry_point: bool,
        is_revoked: bool,
    ) -> DNSKEY {
        DNSKEY {
            flags,
            protocol,
            algorithm,
            public_key,
            key_tag,
            is_zone_key,
            is_secure_entry_point,
            is_revoked,
        }
    }

    pub fn flags(&self) -> u16 {
        self.flags
    }

    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    pub fn algorithm(&self) -> DnssecAlgorithm {
        self.algorithm
    }

    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    pub fn key_tag(&self) -> Option<u16> {
        self.key_tag
    }

    pub fn is_zone_key(&self) -> bool {
        self.is_zone_key
    }

    pub fn is_secure_entry_point(&self) -> bool {
        self.is_secure_entry_point
    }

    pub fn is_revoked(&self) -> bool {
        self.is_revoked
    }
}

/// DS (Delegation Signer) record data: hash of a child zone's DNSKEY.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct DS {
    key_tag: u16,
    algorithm: DnssecAlgorithm,
    digest_type: DigestType,
    digest: String,
}

impl DS {
    pub fn new(key_tag: u16, algorithm: DnssecAlgorithm, digest_type: DigestType, digest: String) -> DS {
        DS {
            key_tag,
            algorithm,
            digest_type,
            digest,
        }
    }

    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    pub fn algorithm(&self) -> DnssecAlgorithm {
        self.algorithm
    }

    pub fn digest_type(&self) -> DigestType {
        self.digest_type
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// RRSIG record data: signature over a DNS record set.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct RRSIG {
    type_covered: String,
    algorithm: DnssecAlgorithm,
    labels: u8,
    original_ttl: u32,
    expiration: u32,
    inception: u32,
    key_tag: u16,
    signer_name: Name,
    signature: String,
}

impl RRSIG {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        type_covered: String,
        algorithm: DnssecAlgorithm,
        labels: u8,
        original_ttl: u32,
        expiration: u32,
        inception: u32,
        key_tag: u16,
        signer_name: Name,
        signature: String,
    ) -> RRSIG {
        RRSIG {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer_name,
            signature,
        }
    }

    pub fn type_covered(&self) -> &str {
        &self.type_covered
    }

    pub fn algorithm(&self) -> DnssecAlgorithm {
        self.algorithm
    }

    pub fn labels(&self) -> u8 {
        self.labels
    }

    pub fn original_ttl(&self) -> u32 {
        self.original_ttl
    }

    pub fn expiration(&self) -> u32 {
        self.expiration
    }

    pub fn inception(&self) -> u32 {
        self.inception
    }

    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    pub fn signer_name(&self) -> &Name {
        &self.signer_name
    }

    pub fn signature(&self) -> &str {
        &self.signature
    }
}

/// NSEC record data: authenticated denial of existence (lists next name and types).
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct NSEC {
    next_domain_name: Name,
    types: Vec<String>,
}

impl NSEC {
    pub fn new(next_domain_name: Name, types: Vec<String>) -> NSEC {
        NSEC {
            next_domain_name,
            types,
        }
    }

    pub fn next_domain_name(&self) -> &Name {
        &self.next_domain_name
    }

    pub fn types(&self) -> &[String] {
        &self.types
    }
}

/// NSEC3 record data: hashed authenticated denial of existence.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct NSEC3 {
    hash_algorithm: String,
    opt_out: bool,
    iterations: u16,
    salt: String,
    next_hashed_owner: String,
    types: Vec<String>,
}

impl NSEC3 {
    pub fn new(
        hash_algorithm: String,
        opt_out: bool,
        iterations: u16,
        salt: String,
        next_hashed_owner: String,
        types: Vec<String>,
    ) -> NSEC3 {
        NSEC3 {
            hash_algorithm,
            opt_out,
            iterations,
            salt,
            next_hashed_owner,
            types,
        }
    }

    pub fn hash_algorithm(&self) -> &str {
        &self.hash_algorithm
    }

    pub fn opt_out(&self) -> bool {
        self.opt_out
    }

    pub fn iterations(&self) -> u16 {
        self.iterations
    }

    pub fn salt(&self) -> &str {
        &self.salt
    }

    pub fn next_hashed_owner(&self) -> &str {
        &self.next_hashed_owner
    }

    pub fn types(&self) -> &[String] {
        &self.types
    }
}

/// NSEC3PARAM record data: parameters for NSEC3 hashing.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct NSEC3PARAM {
    hash_algorithm: String,
    opt_out: bool,
    iterations: u16,
    salt: String,
}

impl NSEC3PARAM {
    pub fn new(hash_algorithm: String, opt_out: bool, iterations: u16, salt: String) -> NSEC3PARAM {
        NSEC3PARAM {
            hash_algorithm,
            opt_out,
            iterations,
            salt,
        }
    }

    pub fn hash_algorithm(&self) -> &str {
        &self.hash_algorithm
    }

    pub fn opt_out(&self) -> bool {
        self.opt_out
    }

    pub fn iterations(&self) -> u16 {
        self.iterations
    }

    pub fn salt(&self) -> &str {
        &self.salt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn dnskey_new_and_accessors() {
        let key = DNSKEY::new(
            257,
            3,
            DnssecAlgorithm::EcdsaP256Sha256,
            "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjj".to_string(),
            Some(2371),
            true,
            true,
            false,
        );
        assert_eq!(key.flags(), 257);
        assert_eq!(key.protocol(), 3);
        assert_eq!(key.algorithm(), DnssecAlgorithm::EcdsaP256Sha256);
        assert!(key.public_key().starts_with("mdsswUyr3DPW"));
        assert_eq!(key.key_tag(), Some(2371));
        assert!(key.is_zone_key());
        assert!(key.is_secure_entry_point());
        assert!(!key.is_revoked());
    }

    #[test]
    fn dnskey_zsk() {
        let key = DNSKEY::new(
            256,
            3,
            DnssecAlgorithm::RsaSha256,
            "AwEAAb...".to_string(),
            Some(12345),
            true,
            false,
            false,
        );
        assert_eq!(key.flags(), 256);
        assert!(key.is_zone_key());
        assert!(!key.is_secure_entry_point());
    }

    #[test]
    fn ds_new_and_accessors() {
        let ds = DS::new(
            2371,
            DnssecAlgorithm::EcdsaP256Sha256,
            DigestType::Sha256,
            "C988EC423E3880EB8DD8A46F".to_string(),
        );
        assert_eq!(ds.key_tag(), 2371);
        assert_eq!(ds.algorithm(), DnssecAlgorithm::EcdsaP256Sha256);
        assert_eq!(ds.digest_type(), DigestType::Sha256);
        assert_eq!(ds.digest(), "C988EC423E3880EB8DD8A46F");
    }

    #[test]
    fn rrsig_new_and_accessors() {
        let name = Name::from_str("example.com.").unwrap();
        let rrsig = RRSIG::new(
            "DNSKEY".to_string(),
            DnssecAlgorithm::EcdsaP256Sha256,
            2,
            3600,
            1700000000,
            1699000000,
            2371,
            name.clone(),
            "c2lnbmF0dXJl".to_string(),
        );
        assert_eq!(rrsig.type_covered(), "DNSKEY");
        assert_eq!(rrsig.algorithm(), DnssecAlgorithm::EcdsaP256Sha256);
        assert_eq!(rrsig.labels(), 2);
        assert_eq!(rrsig.original_ttl(), 3600);
        assert_eq!(rrsig.expiration(), 1700000000);
        assert_eq!(rrsig.inception(), 1699000000);
        assert_eq!(rrsig.key_tag(), 2371);
        assert_eq!(rrsig.signer_name(), &name);
        assert_eq!(rrsig.signature(), "c2lnbmF0dXJl");
    }

    #[test]
    fn nsec_new_and_accessors() {
        let name = Name::from_str("next.example.com.").unwrap();
        let types = vec!["A".to_string(), "AAAA".to_string(), "NS".to_string()];
        let nsec = NSEC::new(name.clone(), types.clone());
        assert_eq!(nsec.next_domain_name(), &name);
        assert_eq!(nsec.types(), &types[..]);
    }

    #[test]
    fn nsec3_new_and_accessors() {
        let nsec3 = NSEC3::new(
            "SHA-1".to_string(),
            false,
            1,
            "ABCD".to_string(),
            "HASH123".to_string(),
            vec!["A".to_string(), "NS".to_string(), "SOA".to_string()],
        );
        assert_eq!(nsec3.hash_algorithm(), "SHA-1");
        assert!(!nsec3.opt_out());
        assert_eq!(nsec3.iterations(), 1);
        assert_eq!(nsec3.salt(), "ABCD");
        assert_eq!(nsec3.next_hashed_owner(), "HASH123");
        assert_eq!(nsec3.types(), &["A", "NS", "SOA"]);
    }

    #[test]
    fn nsec3param_new_and_accessors() {
        let param = NSEC3PARAM::new("SHA-1".to_string(), true, 10, "SALT".to_string());
        assert_eq!(param.hash_algorithm(), "SHA-1");
        assert!(param.opt_out());
        assert_eq!(param.iterations(), 10);
        assert_eq!(param.salt(), "SALT");
    }

    #[test]
    fn dnssec_algorithm_from_u8_known() {
        assert_eq!(DnssecAlgorithm::from(1), DnssecAlgorithm::RsaMd5);
        assert_eq!(DnssecAlgorithm::from(3), DnssecAlgorithm::Dsa);
        assert_eq!(DnssecAlgorithm::from(5), DnssecAlgorithm::RsaSha1);
        assert_eq!(DnssecAlgorithm::from(7), DnssecAlgorithm::RsaSha1Nsec3Sha1);
        assert_eq!(DnssecAlgorithm::from(8), DnssecAlgorithm::RsaSha256);
        assert_eq!(DnssecAlgorithm::from(10), DnssecAlgorithm::RsaSha512);
        assert_eq!(DnssecAlgorithm::from(13), DnssecAlgorithm::EcdsaP256Sha256);
        assert_eq!(DnssecAlgorithm::from(14), DnssecAlgorithm::EcdsaP384Sha384);
        assert_eq!(DnssecAlgorithm::from(15), DnssecAlgorithm::Ed25519);
        assert_eq!(DnssecAlgorithm::from(16), DnssecAlgorithm::Ed448);
    }

    #[test]
    fn dnssec_algorithm_from_u8_unassigned() {
        assert_eq!(DnssecAlgorithm::from(0), DnssecAlgorithm::Unassigned(0));
        assert_eq!(DnssecAlgorithm::from(2), DnssecAlgorithm::Unassigned(2));
        assert_eq!(DnssecAlgorithm::from(255), DnssecAlgorithm::Unassigned(255));
    }

    #[test]
    fn dnssec_algorithm_display() {
        assert_eq!(DnssecAlgorithm::RsaMd5.to_string(), "RSA/MD5");
        assert_eq!(DnssecAlgorithm::EcdsaP256Sha256.to_string(), "ECDSA P-256/SHA-256");
        assert_eq!(DnssecAlgorithm::Ed25519.to_string(), "Ed25519");
        assert_eq!(DnssecAlgorithm::Unassigned(99).to_string(), "Unassigned(99)");
    }

    #[test]
    fn digest_type_from_u8_known() {
        assert_eq!(DigestType::from(1), DigestType::Sha1);
        assert_eq!(DigestType::from(2), DigestType::Sha256);
        assert_eq!(DigestType::from(4), DigestType::Sha384);
    }

    #[test]
    fn digest_type_from_u8_unassigned() {
        assert_eq!(DigestType::from(0), DigestType::Unassigned(0));
        assert_eq!(DigestType::from(3), DigestType::Unassigned(3));
        assert_eq!(DigestType::from(255), DigestType::Unassigned(255));
    }

    #[test]
    fn digest_type_display() {
        assert_eq!(DigestType::Sha1.to_string(), "SHA-1");
        assert_eq!(DigestType::Sha256.to_string(), "SHA-256");
        assert_eq!(DigestType::Sha384.to_string(), "SHA-384");
        assert_eq!(DigestType::Unassigned(5).to_string(), "Unassigned(5)");
    }
}
