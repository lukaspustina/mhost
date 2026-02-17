use super::CheckResult;
use crate::resources::rdata::parsed_txt;

/// Returns true if the given TXT string is a DMARC record.
pub fn is_dmarc(txt: &str) -> bool {
    txt.starts_with("v=DMARC1")
}

/// Run DMARC lint checks against the given DMARC TXT record strings.
pub fn check_dmarc_records(dmarcs: &[String]) -> Vec<CheckResult> {
    let mut results = Vec::new();
    check_num_of_dmarc_records(dmarcs, &mut results);
    check_parsed_dmarc_records(dmarcs, &mut results);
    results
}

fn check_num_of_dmarc_records(dmarcs: &[String], results: &mut Vec<CheckResult>) {
    let check = match dmarcs.len() {
        0 => CheckResult::Warning(
            "No DMARC record found: without DMARC, email spoofing for this domain cannot be detected by receivers"
                .to_string(),
        ),
        1 => CheckResult::Ok("Found exactly one DMARC record".to_string()),
        n => CheckResult::Failed(format!(
            "Found {} DMARC records: a domain must not have multiple DMARC records; cf. RFC 7489, section 6.6.3",
            n
        )),
    };
    results.push(check);
}

fn check_parsed_dmarc_records(dmarcs: &[String], results: &mut Vec<CheckResult>) {
    for txt in dmarcs {
        match parsed_txt::Dmarc::from_str(txt) {
            Ok(dmarc) => {
                results.push(CheckResult::Ok("Successfully parsed DMARC record".to_string()));
                check_dmarc_policy(&dmarc, results);
            }
            Err(_) => {
                results.push(CheckResult::Failed("Failed to parse DMARC record".to_string()));
            }
        }
    }
}

fn check_dmarc_policy(dmarc: &parsed_txt::Dmarc<'_>, results: &mut Vec<CheckResult>) {
    match dmarc.policy() {
        "none" => results.push(CheckResult::Warning(
            "DMARC policy is 'none': emails failing authentication will not be blocked. Consider 'quarantine' or 'reject'"
                .to_string(),
        )),
        "quarantine" => results.push(CheckResult::Ok(
            "DMARC policy is 'quarantine': suspicious emails will be quarantined".to_string(),
        )),
        "reject" => results.push(CheckResult::Ok(
            "DMARC policy is 'reject': emails failing authentication will be rejected".to_string(),
        )),
        other => results.push(CheckResult::Warning(format!(
            "Unknown DMARC policy '{}': expected 'none', 'quarantine', or 'reject'",
            other
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_dmarc_true() {
        assert!(is_dmarc("v=DMARC1; p=reject"));
    }

    #[test]
    fn is_dmarc_false() {
        assert!(!is_dmarc("v=spf1 include:example.com ~all"));
    }

    #[test]
    fn check_num_zero() {
        let mut results = Vec::new();
        check_num_of_dmarc_records(&[], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }

    #[test]
    fn check_num_one() {
        let mut results = Vec::new();
        check_num_of_dmarc_records(&["v=DMARC1; p=reject".to_string()], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn check_num_multiple() {
        let mut results = Vec::new();
        check_num_of_dmarc_records(
            &["v=DMARC1; p=reject".to_string(), "v=DMARC1; p=none".to_string()],
            &mut results,
        );
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Failed(_)));
    }

    #[test]
    fn check_parsed_valid_reject() {
        let mut results = Vec::new();
        check_parsed_dmarc_records(&["v=DMARC1; p=reject".to_string()], &mut results);
        assert_eq!(results.len(), 2);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
        assert!(matches!(&results[1], CheckResult::Ok(_)));
    }

    #[test]
    fn check_parsed_valid_none_policy() {
        let mut results = Vec::new();
        check_parsed_dmarc_records(&["v=DMARC1; p=none".to_string()], &mut results);
        assert_eq!(results.len(), 2);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
        assert!(matches!(&results[1], CheckResult::Warning(_)));
    }

    #[test]
    fn check_parsed_invalid() {
        let mut results = Vec::new();
        check_parsed_dmarc_records(&["garbage data".to_string()], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Failed(_)));
    }

    #[test]
    fn check_policy_quarantine() {
        let dmarc = parsed_txt::Dmarc::from_str("v=DMARC1; p=quarantine").unwrap();
        let mut results = Vec::new();
        check_dmarc_policy(&dmarc, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }
}
