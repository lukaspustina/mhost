// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Shared DNSSEC validation logic used by both the `check` lint and the `dnssec` command.
//!
//! Provides two levels of granularity:
//! - **Per-record classification helpers** (`classify_*`): Evaluate a single record, return one [`Finding`].
//! - **Collection-level validators** (`validate_*`): Evaluate sets of records, return `Vec<Finding>`.

use std::collections::HashSet;

use serde::Serialize;

use crate::resources::rdata::{DnssecAlgorithm, DNSKEY, DS, RRSIG};

/// Severity level for a DNSSEC validation finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Severity {
    Ok,
    Warning,
    Failed,
}

impl Severity {
    /// Returns the worse of two severities (Failed > Warning > Ok).
    pub fn worst(a: &Severity, b: &Severity) -> Severity {
        match (a, b) {
            (Severity::Failed, _) | (_, Severity::Failed) => Severity::Failed,
            (Severity::Warning, _) | (_, Severity::Warning) => Severity::Warning,
            _ => Severity::Ok,
        }
    }
}

/// A single DNSSEC validation finding with severity and human-readable message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub message: String,
}

impl Finding {
    pub fn ok(message: impl Into<String>) -> Finding {
        Finding {
            severity: Severity::Ok,
            message: message.into(),
        }
    }

    pub fn warning(message: impl Into<String>) -> Finding {
        Finding {
            severity: Severity::Warning,
            message: message.into(),
        }
    }

    pub fn failed(message: impl Into<String>) -> Finding {
        Finding {
            severity: Severity::Failed,
            message: message.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Per-record classification helpers
// ---------------------------------------------------------------------------

/// Classify a DNSSEC algorithm by its security strength.
pub fn classify_algorithm(algo: DnssecAlgorithm) -> Finding {
    match algo {
        DnssecAlgorithm::RsaMd5 => Finding::failed(format!("Algorithm {} is deprecated and insecure (RFC 6725)", algo)),
        DnssecAlgorithm::Dsa => Finding::failed(format!("Algorithm {} is deprecated and insecure", algo)),
        DnssecAlgorithm::RsaSha1 | DnssecAlgorithm::RsaSha1Nsec3Sha1 => {
            Finding::warning(format!("Algorithm {}: SHA-1 is deprecated, consider upgrading", algo))
        }
        DnssecAlgorithm::RsaSha256
        | DnssecAlgorithm::RsaSha512
        | DnssecAlgorithm::EcdsaP256Sha256
        | DnssecAlgorithm::EcdsaP384Sha384
        | DnssecAlgorithm::Ed25519
        | DnssecAlgorithm::Ed448 => Finding::ok(format!("Algorithm {} is secure", algo)),
        DnssecAlgorithm::Unassigned(n) => Finding::warning(format!("Unknown DNSSEC algorithm {}", n)),
    }
}

/// Classify an RRSIG's expiration status relative to the current time.
pub fn classify_rrsig_expiration(rrsig: &RRSIG, now: u32) -> Finding {
    const SEVEN_DAYS: u32 = 604800;

    let expiration = rrsig.expiration();
    let inception = rrsig.inception();

    if inception > now {
        return Finding::warning(format!(
            "RRSIG covering {} has inception in the future (key tag {})",
            rrsig.type_covered(),
            rrsig.key_tag()
        ));
    }

    if expiration < now {
        Finding::failed(format!(
            "RRSIG covering {} has expired (key tag {})",
            rrsig.type_covered(),
            rrsig.key_tag()
        ))
    } else if expiration < now.saturating_add(SEVEN_DAYS) {
        let remaining_secs = expiration - now;
        let remaining_days = remaining_secs / 86400;
        Finding::warning(format!(
            "RRSIG covering {} expiring in {} day(s) (key tag {})",
            rrsig.type_covered(),
            remaining_days,
            rrsig.key_tag()
        ))
    } else {
        let remaining_secs = expiration - now;
        let remaining_days = remaining_secs / 86400;
        Finding::ok(format!(
            "RRSIG covering {} valid, expires in {} day(s) (key tag {})",
            rrsig.type_covered(),
            remaining_days,
            rrsig.key_tag()
        ))
    }
}

/// Classify a DS record's binding to a set of DNSKEY records.
pub fn classify_ds_binding(ds: &DS, dnskeys: &[&DNSKEY]) -> Finding {
    let ds_tag = ds.key_tag();
    let matching_key = dnskeys.iter().find(|k| k.key_tag() == Some(ds_tag));

    match matching_key {
        Some(key) => {
            if key.algorithm() != ds.algorithm() {
                Finding::warning(format!(
                    "DS key tag {} matches DNSKEY but algorithm mismatch: DS has {}, DNSKEY has {}",
                    ds_tag,
                    ds.algorithm(),
                    key.algorithm()
                ))
            } else {
                Finding::ok(format!("DS key tag {} matches DNSKEY ({})", ds_tag, key.algorithm()))
            }
        }
        None => Finding::failed(format!(
            "DS key tag {} has no matching DNSKEY: chain of trust is broken",
            ds_tag
        )),
    }
}

// ---------------------------------------------------------------------------
// Collection-level validation functions
// ---------------------------------------------------------------------------

/// Validate algorithm strength across a set of DNSSEC algorithms.
pub fn validate_algorithm_strength(algorithms: &HashSet<DnssecAlgorithm>) -> Vec<Finding> {
    algorithms.iter().map(|algo| classify_algorithm(*algo)).collect()
}

/// Validate RRSIG expiration for a set of RRSIG records.
pub fn validate_rrsig_expiration(rrsigs: &[&RRSIG], now: u32) -> Vec<Finding> {
    rrsigs
        .iter()
        .map(|rrsig| classify_rrsig_expiration(rrsig, now))
        .collect()
}

/// Validate DS-to-DNSKEY binding for a set of DS and DNSKEY records.
pub fn validate_ds_dnskey_binding(ds_records: &[&DS], dnskeys: &[&DNSKEY]) -> Vec<Finding> {
    if ds_records.is_empty() {
        return Vec::new();
    }

    if dnskeys.is_empty() {
        return vec![Finding::failed(
            "DS records exist but no DNSKEY records found: DNSSEC chain of trust is broken",
        )];
    }

    ds_records.iter().map(|ds| classify_ds_binding(ds, dnskeys)).collect()
}

/// Validate that RRSIG records reference existing DNSKEY key tags.
pub fn validate_rrsig_dnskey_binding(rrsigs: &[&RRSIG], dnskeys: &[&DNSKEY]) -> Vec<Finding> {
    if rrsigs.is_empty() || dnskeys.is_empty() {
        return Vec::new();
    }

    let dnskey_tags: HashSet<u16> = dnskeys.iter().filter_map(|k| k.key_tag()).collect();

    // Deduplicate: report each orphaned (type_covered, key_tag) pair once
    let mut reported: HashSet<(String, u16)> = HashSet::new();
    let mut findings = Vec::new();

    for rrsig in rrsigs {
        let tag = rrsig.key_tag();
        if !dnskey_tags.contains(&tag) {
            let key = (rrsig.type_covered().to_string(), tag);
            if reported.insert(key) {
                findings.push(Finding::warning(format!(
                    "RRSIG covering {} references key tag {} not found in DNSKEY set",
                    rrsig.type_covered(),
                    tag
                )));
            }
        }
    }

    findings
}

/// Validate that at least one KSK (secure entry point) exists among DNSKEY records.
pub fn validate_ksk_present(dnskeys: &[&DNSKEY]) -> Vec<Finding> {
    if dnskeys.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let mut ksk_count = 0;
    let mut zsk_count = 0;

    for key in dnskeys {
        if key.is_secure_entry_point() {
            ksk_count += 1;
        } else if key.is_zone_key() {
            zsk_count += 1;
        }
        if key.is_revoked() {
            if let Some(tag) = key.key_tag() {
                findings.push(Finding::warning(format!("DNSKEY key tag {} is revoked", tag)));
            } else {
                findings.push(Finding::warning("DNSKEY is revoked".to_string()));
            }
        }
    }

    if ksk_count == 0 {
        findings.push(Finding::warning(
            "No KSK (secure entry point) found among DNSKEY records".to_string(),
        ));
    } else {
        findings.push(Finding::ok(format!(
            "Found {} KSK(s) and {} ZSK(s)",
            ksk_count, zsk_count
        )));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::rdata::DigestType;
    use crate::Name;
    use std::str::FromStr;

    fn make_dnskey(tag: u16, algo: DnssecAlgorithm, sep: bool, revoked: bool) -> DNSKEY {
        DNSKEY::new(
            if sep { 257 } else { 256 },
            3,
            algo,
            "key_data".to_string(),
            Some(tag),
            true,
            sep,
            revoked,
        )
    }

    fn make_ds(tag: u16, algo: DnssecAlgorithm) -> DS {
        DS::new(tag, algo, DigestType::Sha256, "ABCDEF".to_string())
    }

    fn make_rrsig(type_covered: &str, algo: DnssecAlgorithm, key_tag: u16, expiration: u32, inception: u32) -> RRSIG {
        let name = Name::from_str("example.com.").unwrap();
        RRSIG::new(
            type_covered.to_string(),
            algo,
            2,
            3600,
            expiration,
            inception,
            key_tag,
            name,
            "sig".to_string(),
        )
    }

    // --- Per-record: classify_algorithm ---

    #[test]
    fn classify_algorithm_rsa_md5_failed() {
        let f = classify_algorithm(DnssecAlgorithm::RsaMd5);
        assert_eq!(f.severity, Severity::Failed);
        assert!(f.message.contains("RSA/MD5"));
    }

    #[test]
    fn classify_algorithm_dsa_failed() {
        let f = classify_algorithm(DnssecAlgorithm::Dsa);
        assert_eq!(f.severity, Severity::Failed);
        assert!(f.message.contains("DSA"));
    }

    #[test]
    fn classify_algorithm_rsa_sha1_warning() {
        let f = classify_algorithm(DnssecAlgorithm::RsaSha1);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.message.contains("SHA-1"));
    }

    #[test]
    fn classify_algorithm_ecdsa_p256_ok() {
        let f = classify_algorithm(DnssecAlgorithm::EcdsaP256Sha256);
        assert_eq!(f.severity, Severity::Ok);
        assert!(f.message.contains("secure"));
    }

    #[test]
    fn classify_algorithm_ed25519_ok() {
        let f = classify_algorithm(DnssecAlgorithm::Ed25519);
        assert_eq!(f.severity, Severity::Ok);
        assert!(f.message.contains("Ed25519"));
    }

    #[test]
    fn classify_algorithm_unknown_warning() {
        let f = classify_algorithm(DnssecAlgorithm::Unassigned(200));
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.message.contains("Unknown"));
    }

    // --- Per-record: classify_rrsig_expiration ---

    #[test]
    fn classify_rrsig_expiration_valid() {
        let now: u32 = 1700000000;
        let rrsig = make_rrsig(
            "DNSKEY",
            DnssecAlgorithm::EcdsaP256Sha256,
            2371,
            now + 864000,
            now - 100,
        );
        let f = classify_rrsig_expiration(&rrsig, now);
        assert_eq!(f.severity, Severity::Ok);
        assert!(f.message.contains("valid"));
    }

    #[test]
    fn classify_rrsig_expiration_expired() {
        let now: u32 = 1700000000;
        let rrsig = make_rrsig("A", DnssecAlgorithm::EcdsaP256Sha256, 2371, now - 100, now - 1000);
        let f = classify_rrsig_expiration(&rrsig, now);
        assert_eq!(f.severity, Severity::Failed);
        assert!(f.message.contains("expired"));
    }

    #[test]
    fn classify_rrsig_expiration_near_expiry() {
        let now: u32 = 1700000000;
        let rrsig = make_rrsig("A", DnssecAlgorithm::EcdsaP256Sha256, 2371, now + 259200, now - 100);
        let f = classify_rrsig_expiration(&rrsig, now);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.message.contains("expiring in 3 day(s)"));
    }

    #[test]
    fn classify_rrsig_expiration_future_inception() {
        let now: u32 = 1700000000;
        let rrsig = make_rrsig("A", DnssecAlgorithm::EcdsaP256Sha256, 2371, now + 864000, now + 100);
        let f = classify_rrsig_expiration(&rrsig, now);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.message.contains("inception in the future"));
    }

    // --- Per-record: classify_ds_binding ---

    #[test]
    fn classify_ds_binding_matching() {
        let ds = make_ds(2371, DnssecAlgorithm::EcdsaP256Sha256);
        let key = make_dnskey(2371, DnssecAlgorithm::EcdsaP256Sha256, true, false);
        let f = classify_ds_binding(&ds, &[&key]);
        assert_eq!(f.severity, Severity::Ok);
        assert!(f.message.contains("2371") && f.message.contains("matches"));
    }

    #[test]
    fn classify_ds_binding_no_match() {
        let ds = make_ds(2371, DnssecAlgorithm::EcdsaP256Sha256);
        let key = make_dnskey(9999, DnssecAlgorithm::EcdsaP256Sha256, true, false);
        let f = classify_ds_binding(&ds, &[&key]);
        assert_eq!(f.severity, Severity::Failed);
        assert!(f.message.contains("no matching"));
    }

    #[test]
    fn classify_ds_binding_algorithm_mismatch() {
        let ds = make_ds(2371, DnssecAlgorithm::RsaSha256);
        let key = make_dnskey(2371, DnssecAlgorithm::EcdsaP256Sha256, true, false);
        let f = classify_ds_binding(&ds, &[&key]);
        assert_eq!(f.severity, Severity::Warning);
        assert!(f.message.contains("algorithm mismatch"));
    }

    // --- Collection: validate_algorithm_strength ---

    #[test]
    fn validate_algorithm_strength_deduplicates() {
        let mut algos = HashSet::new();
        algos.insert(DnssecAlgorithm::EcdsaP256Sha256);
        let findings = validate_algorithm_strength(&algos);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Ok);
    }

    // --- Collection: validate_rrsig_expiration ---

    #[test]
    fn validate_rrsig_expiration_multiple() {
        let now: u32 = 1700000000;
        let r1 = make_rrsig("DNSKEY", DnssecAlgorithm::EcdsaP256Sha256, 1, now + 864000, now - 100);
        let r2 = make_rrsig("A", DnssecAlgorithm::EcdsaP256Sha256, 2, now - 100, now - 1000);
        let findings = validate_rrsig_expiration(&[&r1, &r2], now);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::Ok);
        assert_eq!(findings[1].severity, Severity::Failed);
    }

    // --- Collection: validate_ds_dnskey_binding ---

    #[test]
    fn validate_ds_dnskey_binding_empty_ds() {
        let key = make_dnskey(100, DnssecAlgorithm::EcdsaP256Sha256, true, false);
        let findings = validate_ds_dnskey_binding(&[], &[&key]);
        assert!(findings.is_empty());
    }

    #[test]
    fn validate_ds_dnskey_binding_no_dnskeys() {
        let ds = make_ds(100, DnssecAlgorithm::RsaSha1);
        let findings = validate_ds_dnskey_binding(&[&ds], &[]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Failed);
        assert!(findings[0].message.contains("no DNSKEY records found"));
    }

    #[test]
    fn validate_ds_dnskey_binding_matching() {
        let ds = make_ds(2371, DnssecAlgorithm::EcdsaP256Sha256);
        let key = make_dnskey(2371, DnssecAlgorithm::EcdsaP256Sha256, true, false);
        let findings = validate_ds_dnskey_binding(&[&ds], &[&key]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Ok);
    }

    // --- Collection: validate_rrsig_dnskey_binding ---

    #[test]
    fn validate_rrsig_dnskey_binding_matching() {
        let rrsig = make_rrsig("A", DnssecAlgorithm::EcdsaP256Sha256, 2371, 2000000000, 1000000000);
        let key = make_dnskey(2371, DnssecAlgorithm::EcdsaP256Sha256, false, false);
        let findings = validate_rrsig_dnskey_binding(&[&rrsig], &[&key]);
        assert!(findings.is_empty());
    }

    #[test]
    fn validate_rrsig_dnskey_binding_orphaned() {
        let rrsig = make_rrsig("A", DnssecAlgorithm::EcdsaP256Sha256, 5555, 2000000000, 1000000000);
        let key = make_dnskey(2371, DnssecAlgorithm::EcdsaP256Sha256, false, false);
        let findings = validate_rrsig_dnskey_binding(&[&rrsig], &[&key]);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("5555") && findings[0].message.contains("not found"));
    }

    #[test]
    fn validate_rrsig_dnskey_binding_deduplicates() {
        let r1 = make_rrsig("A", DnssecAlgorithm::EcdsaP256Sha256, 5555, 2000000000, 1000000000);
        let r2 = make_rrsig("A", DnssecAlgorithm::EcdsaP256Sha256, 5555, 2000000000, 1000000000);
        let key = make_dnskey(2371, DnssecAlgorithm::EcdsaP256Sha256, false, false);
        let findings = validate_rrsig_dnskey_binding(&[&r1, &r2], &[&key]);
        assert_eq!(findings.len(), 1);
    }

    // --- Collection: validate_ksk_present ---

    #[test]
    fn validate_ksk_present_has_ksk_and_zsk() {
        let ksk = make_dnskey(2371, DnssecAlgorithm::EcdsaP256Sha256, true, false);
        let zsk = make_dnskey(12345, DnssecAlgorithm::EcdsaP256Sha256, false, false);
        let findings = validate_ksk_present(&[&ksk, &zsk]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Ok);
        assert!(findings[0].message.contains("1 KSK") && findings[0].message.contains("1 ZSK"));
    }

    #[test]
    fn validate_ksk_present_no_ksk() {
        let zsk = make_dnskey(12345, DnssecAlgorithm::EcdsaP256Sha256, false, false);
        let findings = validate_ksk_present(&[&zsk]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert!(findings[0].message.contains("No KSK"));
    }

    #[test]
    fn validate_ksk_present_revoked_key() {
        let revoked = make_dnskey(9999, DnssecAlgorithm::RsaSha256, true, true);
        let findings = validate_ksk_present(&[&revoked]);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert!(findings[0].message.contains("revoked"));
        assert_eq!(findings[1].severity, Severity::Ok);
    }

    #[test]
    fn validate_ksk_present_empty() {
        let findings = validate_ksk_present(&[]);
        assert!(findings.is_empty());
    }

    // --- Severity::worst ---

    #[test]
    fn severity_worst_ok_ok() {
        assert_eq!(Severity::worst(&Severity::Ok, &Severity::Ok), Severity::Ok);
    }

    #[test]
    fn severity_worst_ok_warning() {
        assert_eq!(Severity::worst(&Severity::Ok, &Severity::Warning), Severity::Warning);
    }

    #[test]
    fn severity_worst_warning_failed() {
        assert_eq!(Severity::worst(&Severity::Warning, &Severity::Failed), Severity::Failed);
    }
}
