use std::collections::HashMap;

use super::CheckResult;
use crate::resolver::lookup::Uniquify;
use crate::resolver::Lookups;
use crate::resources::rdata::MX;

/// Run synchronous MX lint checks (null MX, duplicate preferences) against the given lookups.
pub fn check_mx_sync(lookups: &Lookups) -> Vec<CheckResult> {
    let unique_mx = lookups.mx().unique();
    let mx_records: Vec<&MX> = unique_mx.iter().collect();
    let mut results = Vec::new();
    if mx_records.is_empty() {
        check_null_mx_absent(&mut results);
    } else {
        check_null_mx(&mx_records, &mut results);
        check_duplicate_preferences(&mx_records, &mut results);
    }
    results
}

fn check_null_mx_absent(results: &mut Vec<CheckResult>) {
    results.push(CheckResult::Warning(
        "No MX records found: if this domain does not handle mail, consider adding a Null MX record (RFC 7505)"
            .to_string(),
    ));
}

fn check_null_mx(mx_records: &[&MX], results: &mut Vec<CheckResult>) {
    let has_null_mx = mx_records
        .iter()
        .any(|mx| mx.preference() == 0 && mx.exchange().is_root());

    if has_null_mx {
        if mx_records.len() > 1 {
            results.push(CheckResult::Failed(
                "Null MX (preference 0, target '.') must be the only MX record; cf. RFC 7505".to_string(),
            ));
        } else {
            results.push(CheckResult::Ok(
                "Domain has a valid Null MX record (RFC 7505)".to_string(),
            ));
        }
    }
}

fn check_duplicate_preferences(mx_records: &[&MX], results: &mut Vec<CheckResult>) {
    let mut pref_counts: HashMap<u16, usize> = HashMap::new();
    for mx in mx_records {
        *pref_counts.entry(mx.preference()).or_insert(0) += 1;
    }

    let duplicates: Vec<u16> = pref_counts
        .iter()
        .filter(|(_, count)| **count > 1)
        .map(|(pref, _)| *pref)
        .collect();

    if duplicates.is_empty() {
        results.push(CheckResult::Ok("All MX records have unique preferences".to_string()));
    } else {
        results.push(CheckResult::Warning(format!(
            "Duplicate MX preferences found: {:?}. While valid, this may indicate a misconfiguration",
            duplicates
        )));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Name;
    use std::str::FromStr;

    #[test]
    fn check_null_mx_absent_produces_warning() {
        let mut results = Vec::new();
        check_null_mx_absent(&mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }

    #[test]
    fn check_null_mx_valid_single() {
        let mut results = Vec::new();
        let null_mx = MX::new(0, Name::root());
        let records = vec![&null_mx];
        check_null_mx(&records, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn check_null_mx_with_other_records() {
        let mut results = Vec::new();
        let null_mx = MX::new(0, Name::root());
        let regular_mx = MX::new(10, Name::from_str("mail.example.com.").unwrap());
        let records = vec![&null_mx, &regular_mx];
        check_null_mx(&records, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Failed(_)));
    }

    #[test]
    fn check_duplicate_preferences_unique() {
        let mut results = Vec::new();
        let mx1 = MX::new(10, Name::from_str("mx1.example.com.").unwrap());
        let mx2 = MX::new(20, Name::from_str("mx2.example.com.").unwrap());
        let records = vec![&mx1, &mx2];
        check_duplicate_preferences(&records, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn check_duplicate_preferences_duplicated() {
        let mut results = Vec::new();
        let mx1 = MX::new(10, Name::from_str("mx1.example.com.").unwrap());
        let mx2 = MX::new(10, Name::from_str("mx2.example.com.").unwrap());
        let records = vec![&mx1, &mx2];
        check_duplicate_preferences(&records, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }
}
