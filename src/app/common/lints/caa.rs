use super::CheckResult;
use crate::resolver::lookup::Uniquify;
use crate::resolver::Lookups;
use crate::resources::rdata::CAA;

/// Run CAA lint checks against the given lookups.
pub fn check_caa(lookups: &Lookups) -> Vec<CheckResult> {
    let unique_caa = lookups.caa().unique();
    let caa_records: Vec<&CAA> = unique_caa.iter().collect();
    let mut results = Vec::new();
    check_caa_presence(&caa_records, &mut results);
    if !caa_records.is_empty() {
        check_caa_tags(&caa_records, &mut results);
        check_issuewild_coverage(&caa_records, &mut results);
    }
    results
}

fn check_caa_presence(caa_records: &[&CAA], results: &mut Vec<CheckResult>) {
    if caa_records.is_empty() {
        results.push(CheckResult::Warning(
            "No CAA records found: any Certificate Authority can issue certificates for this domain; cf. RFC 8659"
                .to_string(),
        ));
    } else {
        results.push(CheckResult::Ok(format!(
            "Found {} CAA record(s) restricting certificate issuance",
            caa_records.len()
        )));
    }
}

fn check_caa_tags(caa_records: &[&CAA], results: &mut Vec<CheckResult>) {
    let known_tags = ["issue", "issuewild", "iodef"];
    let unknown_tags: Vec<&str> = caa_records
        .iter()
        .map(|caa| caa.tag())
        .filter(|tag| !known_tags.contains(tag))
        .collect();

    if !unknown_tags.is_empty() {
        results.push(CheckResult::Warning(format!(
            "Unknown CAA tag(s): {}. Known tags are: issue, issuewild, iodef",
            unknown_tags.join(", ")
        )));
    }
}

fn check_issuewild_coverage(caa_records: &[&CAA], results: &mut Vec<CheckResult>) {
    let has_issue = caa_records.iter().any(|caa| caa.tag() == "issue");
    let has_issuewild = caa_records.iter().any(|caa| caa.tag() == "issuewild");

    if has_issue && !has_issuewild {
        results.push(CheckResult::Warning(
            "CAA 'issue' is set but 'issuewild' is not: wildcard certificate issuance is unrestricted".to_string(),
        ));
    } else if has_issue && has_issuewild {
        results.push(CheckResult::Ok(
            "Both 'issue' and 'issuewild' CAA tags are configured".to_string(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_presence_empty() {
        let mut results = Vec::new();
        check_caa_presence(&[], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }

    #[test]
    fn check_presence_found() {
        let mut results = Vec::new();
        let caa = CAA::new(false, "issue".to_string(), "letsencrypt.org".to_string());
        check_caa_presence(&[&caa], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn check_tags_valid() {
        let mut results = Vec::new();
        let caa1 = CAA::new(false, "issue".to_string(), "letsencrypt.org".to_string());
        let caa2 = CAA::new(false, "issuewild".to_string(), ";".to_string());
        let caa3 = CAA::new(false, "iodef".to_string(), "mailto:admin@example.com".to_string());
        check_caa_tags(&[&caa1, &caa2, &caa3], &mut results);
        assert!(results.is_empty());
    }

    #[test]
    fn check_tags_unknown() {
        let mut results = Vec::new();
        let caa = CAA::new(false, "badtag".to_string(), "value".to_string());
        check_caa_tags(&[&caa], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }

    #[test]
    fn check_issuewild_both_present() {
        let mut results = Vec::new();
        let caa1 = CAA::new(false, "issue".to_string(), "letsencrypt.org".to_string());
        let caa2 = CAA::new(false, "issuewild".to_string(), ";".to_string());
        check_issuewild_coverage(&[&caa1, &caa2], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn check_issuewild_missing() {
        let mut results = Vec::new();
        let caa = CAA::new(false, "issue".to_string(), "letsencrypt.org".to_string());
        check_issuewild_coverage(&[&caa], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }
}
