use super::CheckResult;
use crate::diff::Differ;
use crate::resolver::lookup::Uniquify;
use crate::resolver::Lookups;
use crate::resources::rdata::{parsed_txt, TXT};

/// Run SPF lint checks against the given lookups.
pub fn check_spf(lookups: &Lookups) -> Vec<CheckResult> {
    let spfs: Vec<String> = lookups
        .txt()
        .unique()
        .iter()
        .filter(|x| x.is_spf())
        .map(TXT::as_string)
        .collect();
    let mut results = Vec::new();
    check_num_of_spf_records(&spfs, &mut results);
    check_parsed_spf_records(&spfs, &mut results);
    results
}

fn check_num_of_spf_records(spfs: &[String], results: &mut Vec<CheckResult>) {
    let check = match spfs.len() {
        0 => CheckResult::NotFound(),
        1 => CheckResult::Ok("Found exactly one SPF record".to_string()),
        n => CheckResult::Failed(format!(
            "Found {} SPF records: A domain must not have multiple records; cf. RFC 4408, section 3.1.2",
            n
        )),
    };
    results.push(check);
}

fn check_parsed_spf_records(spfs: &[String], results: &mut Vec<CheckResult>) {
    // Check, if Txt records can be parsed into SPF records
    let mut parsed_spfs = Vec::new();
    for str in spfs {
        if let Ok(spf) = parsed_txt::Spf::from_str(str) {
            results.push(CheckResult::Ok("Successfully parsed SPF record".to_string()));
            parsed_spfs.push(spf)
        } else {
            results.push(CheckResult::Failed("Failed to parse SPF record".to_string()));
        }
    }

    // If there are multiple parsable SPF records, check if they at least are the same
    if parsed_spfs.len() > 1 {
        let mut it = parsed_spfs.into_iter();
        let first = it.next().unwrap();
        for next in it {
            if first.difference(&next).is_some() {
                results.push(CheckResult::Warning("Spf records differ".to_string()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn num_spf_zero() {
        let mut results = Vec::new();
        check_num_of_spf_records(&[], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::NotFound()));
    }

    #[test]
    fn num_spf_one() {
        let mut results = Vec::new();
        let spfs = vec!["v=spf1 -all".to_string()];
        check_num_of_spf_records(&spfs, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn num_spf_multiple() {
        let mut results = Vec::new();
        let spfs = vec!["v=spf1 -all".to_string(), "v=spf1 +all".to_string()];
        check_num_of_spf_records(&spfs, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Failed(_)));
    }

    #[test]
    fn parsed_valid_spf() {
        let mut results = Vec::new();
        let spfs = vec!["v=spf1 ip4:192.0.2.0/24 -all".to_string()];
        check_parsed_spf_records(&spfs, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn parsed_invalid_spf() {
        let mut results = Vec::new();
        let spfs = vec!["v=spfx not-valid".to_string()];
        check_parsed_spf_records(&spfs, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Failed(_)));
    }

    #[test]
    fn parsed_multiple_identical() {
        let mut results = Vec::new();
        let spfs = vec![
            "v=spf1 ip4:192.0.2.0/24 -all".to_string(),
            "v=spf1 ip4:192.0.2.0/24 -all".to_string(),
        ];
        check_parsed_spf_records(&spfs, &mut results);
        // Two Ok results for successful parsing, no Warning for identical records
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| matches!(r, CheckResult::Ok(_))));
    }

    #[test]
    fn parsed_multiple_differing() {
        let mut results = Vec::new();
        let spfs = vec![
            "v=spf1 ip4:192.0.2.0/24 -all".to_string(),
            "v=spf1 ip4:198.51.100.0/24 -all".to_string(),
        ];
        check_parsed_spf_records(&spfs, &mut results);
        // Two Ok results for parsing + one Warning for differing
        assert_eq!(results.len(), 3);
        assert!(results.iter().any(|r| matches!(r, CheckResult::Warning(_))));
    }
}
