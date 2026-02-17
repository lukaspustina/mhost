use super::CheckResult;
use crate::resolver::lookup::Uniquify;
use crate::resolver::Lookups;
use crate::Name;

/// Run synchronous NS count lint check against the given lookups.
pub fn check_ns_count(lookups: &Lookups) -> Vec<CheckResult> {
    let ns_names: Vec<Name> = lookups.ns().unique().to_owned().into_iter().collect();
    let mut results = Vec::new();
    check_minimum_ns_count(&ns_names, &mut results);
    results
}

fn check_minimum_ns_count(ns_names: &[Name], results: &mut Vec<CheckResult>) {
    match ns_names.len() {
        0 => results.push(CheckResult::NotFound()),
        1 => results.push(CheckResult::Warning(
            "Only 1 NS record found: RFC 1035 recommends at least 2 nameservers for redundancy".to_string(),
        )),
        n => results.push(CheckResult::Ok(format!(
            "Found {} NS records, meeting minimum redundancy requirement",
            n
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_minimum_ns_count_zero() {
        let mut results = Vec::new();
        check_minimum_ns_count(&[], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::NotFound()));
    }

    #[test]
    fn check_minimum_ns_count_one() {
        let mut results = Vec::new();
        let names = vec![Name::from_ascii("ns1.example.com.").unwrap()];
        check_minimum_ns_count(&names, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }

    #[test]
    fn check_minimum_ns_count_two() {
        let mut results = Vec::new();
        let names = vec![
            Name::from_ascii("ns1.example.com.").unwrap(),
            Name::from_ascii("ns2.example.com.").unwrap(),
        ];
        check_minimum_ns_count(&names, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }
}
