use super::CheckResult;
use crate::resolver::Lookups;
use crate::resources::dnssec_validation::{self, Finding, Severity};

struct DnssecCounts {
    dnskey: usize,
    ds: usize,
    rrsig: usize,
    nsec: usize,
    nsec3: usize,
    nsec3param: usize,
}

impl DnssecCounts {
    fn total(&self) -> usize {
        self.dnskey + self.ds + self.rrsig + self.nsec + self.nsec3 + self.nsec3param
    }
}

/// Run DNSSEC lint checks against the given lookups.
pub fn check_dnssec(lookups: &Lookups) -> Vec<CheckResult> {
    let mut results = Vec::new();

    let counts = DnssecCounts {
        dnskey: lookups.dnskey().len(),
        ds: lookups.ds().len(),
        rrsig: lookups.rrsig().len(),
        nsec: lookups.nsec().len(),
        nsec3: lookups.nsec3().len(),
        nsec3param: lookups.nsec3param().len(),
    };

    check_dnssec_presence(&counts, &mut results);

    if counts.total() > 0 {
        check_dnssec_key_types(counts.dnskey > 0, counts.rrsig > 0, &mut results);

        let dnskeys = lookups.dnskey();
        let ds_records = lookups.ds();
        let rrsigs = lookups.rrsig();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);

        check_ksk_present(&dnskeys, &mut results);
        check_ds_dnskey_binding(&ds_records, &dnskeys, &mut results);
        check_rrsig_dnskey_binding(&rrsigs, &dnskeys, &mut results);
        check_rrsig_expiration(&rrsigs, now, &mut results);
        check_algorithm_strength(&dnskeys, &rrsigs, &mut results);
    }

    results
}

fn check_dnssec_presence(counts: &DnssecCounts, results: &mut Vec<CheckResult>) {
    if counts.total() == 0 {
        results.push(CheckResult::Warning(
            "No DNSSEC records found: domain is not DNSSEC-signed, DNS responses cannot be authenticated".to_string(),
        ));
    } else {
        let mut types = Vec::new();
        if counts.dnskey > 0 {
            types.push("DNSKEY");
        }
        if counts.ds > 0 {
            types.push("DS");
        }
        if counts.rrsig > 0 {
            types.push("RRSIG");
        }
        if counts.nsec > 0 {
            types.push("NSEC");
        }
        if counts.nsec3 > 0 {
            types.push("NSEC3");
        }
        if counts.nsec3param > 0 {
            types.push("NSEC3PARAM");
        }
        results.push(CheckResult::Ok(format!(
            "Domain has DNSSEC records: {}",
            types.join(", ")
        )));
    }
}

fn check_dnssec_key_types(has_dnskey: bool, has_rrsig: bool, results: &mut Vec<CheckResult>) {
    if has_dnskey && has_rrsig {
        results.push(CheckResult::Ok(
            "DNSKEY and RRSIG records present: DNSSEC chain appears complete".to_string(),
        ));
    } else if has_dnskey && !has_rrsig {
        results.push(CheckResult::Warning(
            "DNSKEY present but no RRSIG records found: DNSSEC signatures may be missing".to_string(),
        ));
    } else if !has_dnskey && has_rrsig {
        results.push(CheckResult::Warning(
            "RRSIG present but no DNSKEY records found: DNSSEC validation may fail".to_string(),
        ));
    }
}

fn check_ksk_present(dnskeys: &[&crate::resources::rdata::DNSKEY], results: &mut Vec<CheckResult>) {
    results.extend(
        dnssec_validation::validate_ksk_present(dnskeys)
            .into_iter()
            .map(finding_to_check_result),
    );
}

fn check_ds_dnskey_binding(
    ds_records: &[&crate::resources::rdata::DS],
    dnskeys: &[&crate::resources::rdata::DNSKEY],
    results: &mut Vec<CheckResult>,
) {
    results.extend(
        dnssec_validation::validate_ds_dnskey_binding(ds_records, dnskeys)
            .into_iter()
            .map(finding_to_check_result),
    );
}

fn check_rrsig_dnskey_binding(
    rrsigs: &[&crate::resources::rdata::RRSIG],
    dnskeys: &[&crate::resources::rdata::DNSKEY],
    results: &mut Vec<CheckResult>,
) {
    results.extend(
        dnssec_validation::validate_rrsig_dnskey_binding(rrsigs, dnskeys)
            .into_iter()
            .map(finding_to_check_result),
    );
}

fn check_rrsig_expiration(rrsigs: &[&crate::resources::rdata::RRSIG], now: u32, results: &mut Vec<CheckResult>) {
    // Only check DNSKEY-covering RRSIGs — other RRSIGs (HINFO, A, etc.)
    // commonly have short lifetimes and are not relevant to chain integrity.
    let dnskey_rrsigs: Vec<&crate::resources::rdata::RRSIG> = rrsigs
        .iter()
        .filter(|r| r.type_covered() == "DNSKEY")
        .copied()
        .collect();
    let findings = dnssec_validation::validate_rrsig_expiration(&dnskey_rrsigs, now);
    for (finding, rrsig) in findings.into_iter().zip(dnskey_rrsigs.iter()) {
        match finding.severity {
            Severity::Ok => {
                let remaining_secs = rrsig.expiration() - now;
                let remaining_days = remaining_secs / 86400;
                results.push(CheckResult::Ok(format!(
                    "DNSKEY RRSIG valid, expires in {} day(s) (key tag {})",
                    remaining_days,
                    rrsig.key_tag()
                )));
            }
            _ => results.push(finding_to_check_result(finding)),
        }
    }
}

fn check_algorithm_strength(
    dnskeys: &[&crate::resources::rdata::DNSKEY],
    rrsigs: &[&crate::resources::rdata::RRSIG],
    results: &mut Vec<CheckResult>,
) {
    let mut seen = std::collections::HashSet::new();
    for key in dnskeys {
        seen.insert(key.algorithm());
    }
    for rrsig in rrsigs {
        seen.insert(rrsig.algorithm());
    }
    results.extend(
        dnssec_validation::validate_algorithm_strength(&seen)
            .into_iter()
            .map(finding_to_check_result),
    );
}

fn finding_to_check_result(finding: Finding) -> CheckResult {
    match finding.severity {
        Severity::Ok => CheckResult::Ok(finding.message),
        Severity::Warning => CheckResult::Warning(finding.message),
        Severity::Failed => CheckResult::Failed(finding.message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::rdata::{DigestType, DnssecAlgorithm, DNSKEY, DS, RRSIG};
    use crate::Name;
    use std::str::FromStr;

    fn counts(dnskey: usize, ds: usize, rrsig: usize, nsec: usize, nsec3: usize, nsec3param: usize) -> DnssecCounts {
        DnssecCounts {
            dnskey,
            ds,
            rrsig,
            nsec,
            nsec3,
            nsec3param,
        }
    }

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

    // --- Existing tests ---

    #[test]
    fn check_presence_empty() {
        let mut results = Vec::new();
        check_dnssec_presence(&counts(0, 0, 0, 0, 0, 0), &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }

    #[test]
    fn check_presence_found() {
        let mut results = Vec::new();
        check_dnssec_presence(&counts(1, 0, 1, 0, 0, 0), &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn check_key_types_complete() {
        let mut results = Vec::new();
        check_dnssec_key_types(true, true, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn check_key_types_missing_rrsig() {
        let mut results = Vec::new();
        check_dnssec_key_types(true, false, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }

    #[test]
    fn check_key_types_missing_dnskey() {
        let mut results = Vec::new();
        check_dnssec_key_types(false, true, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }

    // --- KSK present tests ---

    #[test]
    fn check_ksk_present_has_ksk_and_zsk() {
        let ksk = make_dnskey(2371, DnssecAlgorithm::EcdsaP256Sha256, true, false);
        let zsk = make_dnskey(12345, DnssecAlgorithm::EcdsaP256Sha256, false, false);
        let dnskeys: Vec<&DNSKEY> = vec![&ksk, &zsk];
        let mut results = Vec::new();

        check_ksk_present(&dnskeys, &mut results);

        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(msg) if msg.contains("1 KSK") && msg.contains("1 ZSK")));
    }

    #[test]
    fn check_ksk_present_no_ksk() {
        let zsk = make_dnskey(12345, DnssecAlgorithm::EcdsaP256Sha256, false, false);
        let dnskeys: Vec<&DNSKEY> = vec![&zsk];
        let mut results = Vec::new();

        check_ksk_present(&dnskeys, &mut results);

        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(msg) if msg.contains("No KSK")));
    }

    #[test]
    fn check_ksk_present_revoked_key() {
        let revoked = make_dnskey(9999, DnssecAlgorithm::RsaSha256, true, true);
        let dnskeys: Vec<&DNSKEY> = vec![&revoked];
        let mut results = Vec::new();

        check_ksk_present(&dnskeys, &mut results);

        assert_eq!(results.len(), 2);
        assert!(matches!(&results[0], CheckResult::Warning(msg) if msg.contains("revoked")));
        assert!(matches!(&results[1], CheckResult::Ok(msg) if msg.contains("1 KSK")));
    }

    #[test]
    fn check_ksk_present_empty() {
        let dnskeys: Vec<&DNSKEY> = vec![];
        let mut results = Vec::new();

        check_ksk_present(&dnskeys, &mut results);

        assert!(results.is_empty());
    }

    // --- DS-DNSKEY binding tests ---

    #[test]
    fn check_ds_dnskey_binding_matching() {
        let ds = make_ds(2371, DnssecAlgorithm::EcdsaP256Sha256);
        let key = make_dnskey(2371, DnssecAlgorithm::EcdsaP256Sha256, true, false);
        let ds_records: Vec<&DS> = vec![&ds];
        let dnskeys: Vec<&DNSKEY> = vec![&key];
        let mut results = Vec::new();

        check_ds_dnskey_binding(&ds_records, &dnskeys, &mut results);

        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(msg) if msg.contains("2371") && msg.contains("matches")));
    }

    #[test]
    fn check_ds_dnskey_binding_ds_without_dnskey() {
        let ds = make_ds(106, DnssecAlgorithm::RsaSha1);
        let ds_records: Vec<&DS> = vec![&ds];
        let dnskeys: Vec<&DNSKEY> = vec![];
        let mut results = Vec::new();

        check_ds_dnskey_binding(&ds_records, &dnskeys, &mut results);

        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Failed(msg) if msg.contains("no DNSKEY records found")));
    }

    #[test]
    fn check_ds_dnskey_binding_no_match() {
        let ds = make_ds(2371, DnssecAlgorithm::EcdsaP256Sha256);
        let key = make_dnskey(9999, DnssecAlgorithm::EcdsaP256Sha256, true, false);
        let ds_records: Vec<&DS> = vec![&ds];
        let dnskeys: Vec<&DNSKEY> = vec![&key];
        let mut results = Vec::new();

        check_ds_dnskey_binding(&ds_records, &dnskeys, &mut results);

        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Failed(msg) if msg.contains("2371") && msg.contains("no matching")));
    }

    #[test]
    fn check_ds_dnskey_binding_algorithm_mismatch() {
        let ds = make_ds(2371, DnssecAlgorithm::RsaSha256);
        let key = make_dnskey(2371, DnssecAlgorithm::EcdsaP256Sha256, true, false);
        let ds_records: Vec<&DS> = vec![&ds];
        let dnskeys: Vec<&DNSKEY> = vec![&key];
        let mut results = Vec::new();

        check_ds_dnskey_binding(&ds_records, &dnskeys, &mut results);

        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(msg) if msg.contains("algorithm mismatch")));
    }

    // --- RRSIG-DNSKEY binding tests ---

    #[test]
    fn check_rrsig_dnskey_binding_matching() {
        let rrsig = make_rrsig("A", DnssecAlgorithm::EcdsaP256Sha256, 2371, 2000000000, 1000000000);
        let key = make_dnskey(2371, DnssecAlgorithm::EcdsaP256Sha256, false, false);
        let rrsigs: Vec<&RRSIG> = vec![&rrsig];
        let dnskeys: Vec<&DNSKEY> = vec![&key];
        let mut results = Vec::new();

        check_rrsig_dnskey_binding(&rrsigs, &dnskeys, &mut results);

        assert!(results.is_empty());
    }

    #[test]
    fn check_rrsig_dnskey_binding_orphaned() {
        let rrsig = make_rrsig("A", DnssecAlgorithm::EcdsaP256Sha256, 5555, 2000000000, 1000000000);
        let key = make_dnskey(2371, DnssecAlgorithm::EcdsaP256Sha256, false, false);
        let rrsigs: Vec<&RRSIG> = vec![&rrsig];
        let dnskeys: Vec<&DNSKEY> = vec![&key];
        let mut results = Vec::new();

        check_rrsig_dnskey_binding(&rrsigs, &dnskeys, &mut results);

        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(msg) if msg.contains("5555") && msg.contains("not found")));
    }

    #[test]
    fn check_rrsig_dnskey_binding_deduplicates() {
        let rrsig1 = make_rrsig("A", DnssecAlgorithm::EcdsaP256Sha256, 5555, 2000000000, 1000000000);
        let rrsig2 = make_rrsig("A", DnssecAlgorithm::EcdsaP256Sha256, 5555, 2000000000, 1000000000);
        let key = make_dnskey(2371, DnssecAlgorithm::EcdsaP256Sha256, false, false);
        let rrsigs: Vec<&RRSIG> = vec![&rrsig1, &rrsig2];
        let dnskeys: Vec<&DNSKEY> = vec![&key];
        let mut results = Vec::new();

        check_rrsig_dnskey_binding(&rrsigs, &dnskeys, &mut results);

        assert_eq!(results.len(), 1);
    }

    // --- RRSIG expiration tests ---

    #[test]
    fn check_rrsig_expiration_valid() {
        let now: u32 = 1700000000;
        let rrsig = make_rrsig(
            "DNSKEY",
            DnssecAlgorithm::EcdsaP256Sha256,
            2371,
            now + 864000,
            now - 100,
        );
        let rrsigs: Vec<&RRSIG> = vec![&rrsig];
        let mut results = Vec::new();

        check_rrsig_expiration(&rrsigs, now, &mut results);

        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(msg) if msg.contains("DNSKEY RRSIG valid")));
    }

    #[test]
    fn check_rrsig_expiration_expired() {
        let now: u32 = 1700000000;
        let rrsig = make_rrsig("DNSKEY", DnssecAlgorithm::EcdsaP256Sha256, 2371, now - 100, now - 1000);
        let rrsigs: Vec<&RRSIG> = vec![&rrsig];
        let mut results = Vec::new();

        check_rrsig_expiration(&rrsigs, now, &mut results);

        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Failed(msg) if msg.contains("expired")));
    }

    #[test]
    fn check_rrsig_expiration_near_expiry() {
        let now: u32 = 1700000000;
        // Expires in 3 days (less than 7 day threshold)
        let rrsig = make_rrsig(
            "DNSKEY",
            DnssecAlgorithm::EcdsaP256Sha256,
            2371,
            now + 259200,
            now - 100,
        );
        let rrsigs: Vec<&RRSIG> = vec![&rrsig];
        let mut results = Vec::new();

        check_rrsig_expiration(&rrsigs, now, &mut results);

        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(msg) if msg.contains("expiring in 3 day(s)")));
    }

    #[test]
    fn check_rrsig_expiration_future_inception() {
        let now: u32 = 1700000000;
        let rrsig = make_rrsig(
            "DNSKEY",
            DnssecAlgorithm::EcdsaP256Sha256,
            2371,
            now + 864000,
            now + 100,
        );
        let rrsigs: Vec<&RRSIG> = vec![&rrsig];
        let mut results = Vec::new();

        check_rrsig_expiration(&rrsigs, now, &mut results);

        // Should have both a future inception warning and the expiration status
        assert!(results
            .iter()
            .any(|r| matches!(r, CheckResult::Warning(msg) if msg.contains("inception in the future"))));
    }

    // --- Algorithm strength tests ---

    #[test]
    fn check_algorithm_strength_rsa_md5() {
        let key = make_dnskey(100, DnssecAlgorithm::RsaMd5, true, false);
        let dnskeys: Vec<&DNSKEY> = vec![&key];
        let rrsigs: Vec<&RRSIG> = vec![];
        let mut results = Vec::new();

        check_algorithm_strength(&dnskeys, &rrsigs, &mut results);

        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Failed(msg) if msg.contains("RSA/MD5") && msg.contains("RFC 6725")));
    }

    #[test]
    fn check_algorithm_strength_dsa() {
        let key = make_dnskey(100, DnssecAlgorithm::Dsa, true, false);
        let dnskeys: Vec<&DNSKEY> = vec![&key];
        let rrsigs: Vec<&RRSIG> = vec![];
        let mut results = Vec::new();

        check_algorithm_strength(&dnskeys, &rrsigs, &mut results);

        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Failed(msg) if msg.contains("DSA") && msg.contains("insecure")));
    }

    #[test]
    fn check_algorithm_strength_rsa_sha1() {
        let key = make_dnskey(100, DnssecAlgorithm::RsaSha1, true, false);
        let dnskeys: Vec<&DNSKEY> = vec![&key];
        let rrsigs: Vec<&RRSIG> = vec![];
        let mut results = Vec::new();

        check_algorithm_strength(&dnskeys, &rrsigs, &mut results);

        assert_eq!(results.len(), 1);
        assert!(
            matches!(&results[0], CheckResult::Warning(msg) if msg.contains("SHA-1") && msg.contains("deprecated"))
        );
    }

    #[test]
    fn check_algorithm_strength_ecdsa_p256() {
        let key = make_dnskey(100, DnssecAlgorithm::EcdsaP256Sha256, true, false);
        let dnskeys: Vec<&DNSKEY> = vec![&key];
        let rrsigs: Vec<&RRSIG> = vec![];
        let mut results = Vec::new();

        check_algorithm_strength(&dnskeys, &rrsigs, &mut results);

        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(msg) if msg.contains("secure")));
    }

    #[test]
    fn check_algorithm_strength_ed25519() {
        let key = make_dnskey(100, DnssecAlgorithm::Ed25519, true, false);
        let dnskeys: Vec<&DNSKEY> = vec![&key];
        let rrsigs: Vec<&RRSIG> = vec![];
        let mut results = Vec::new();

        check_algorithm_strength(&dnskeys, &rrsigs, &mut results);

        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(msg) if msg.contains("Ed25519") && msg.contains("secure")));
    }

    #[test]
    fn check_algorithm_strength_deduplicates() {
        let key = make_dnskey(100, DnssecAlgorithm::EcdsaP256Sha256, true, false);
        let rrsig = make_rrsig("A", DnssecAlgorithm::EcdsaP256Sha256, 100, 2000000000, 1000000000);
        let dnskeys: Vec<&DNSKEY> = vec![&key];
        let rrsigs: Vec<&RRSIG> = vec![&rrsig];
        let mut results = Vec::new();

        check_algorithm_strength(&dnskeys, &rrsigs, &mut results);

        // Same algorithm from both DNSKEY and RRSIG should only be reported once
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn check_algorithm_strength_unknown() {
        let key = make_dnskey(100, DnssecAlgorithm::Unassigned(200), true, false);
        let dnskeys: Vec<&DNSKEY> = vec![&key];
        let rrsigs: Vec<&RRSIG> = vec![];
        let mut results = Vec::new();

        check_algorithm_strength(&dnskeys, &rrsigs, &mut results);

        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(msg) if msg.contains("Unknown")));
    }
}
