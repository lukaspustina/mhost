use super::CheckResult;
use crate::resolver::lookup::Uniquify;
use crate::resolver::Lookups;
use crate::resources::rdata::SVCB;

/// Run synchronous HTTPS/SVCB mode lint checks against the given lookups.
pub fn check_https_svcb_mode(lookups: &Lookups) -> Vec<CheckResult> {
    let mut results = Vec::new();
    let unique_https = lookups.https().unique();
    let https_records: Vec<&SVCB> = unique_https.iter().collect();
    let unique_svcb = lookups.svcb().unique();
    let svcb_records: Vec<&SVCB> = unique_svcb.iter().collect();
    if https_records.is_empty() && svcb_records.is_empty() {
        results.push(CheckResult::NotFound());
    } else {
        if !https_records.is_empty() {
            check_svcb_records("HTTPS", &https_records, &mut results);
        }
        if !svcb_records.is_empty() {
            check_svcb_records("SVCB", &svcb_records, &mut results);
        }
    }
    results
}

fn check_svcb_records(record_type: &str, records: &[&SVCB], results: &mut Vec<CheckResult>) {
    let alias_count = records.iter().filter(|r| r.is_alias()).count();
    let service_count = records.len() - alias_count;

    if alias_count > 0 && service_count > 0 {
        results.push(CheckResult::Warning(format!(
            "{} records mix alias (priority 0) and service modes: this may cause inconsistent behavior; cf. RFC 9460",
            record_type
        )));
    } else if alias_count > 1 {
        results.push(CheckResult::Warning(format!(
            "Multiple {} alias records found: only one alias record is expected; cf. RFC 9460",
            record_type
        )));
    } else {
        results.push(CheckResult::Ok(format!(
            "{} records are well-formed ({} alias, {} service mode)",
            record_type, alias_count, service_count
        )));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Name;
    use std::str::FromStr;

    #[test]
    fn check_svcb_records_service_only() {
        let mut results = Vec::new();
        let target = Name::from_str("cdn.example.com.").unwrap();
        let svc = SVCB::new(1, target, vec![]);
        check_svcb_records("HTTPS", &[&svc], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn check_svcb_records_alias_only() {
        let mut results = Vec::new();
        let target = Name::from_str("other.example.com.").unwrap();
        let alias = SVCB::new(0, target, vec![]);
        check_svcb_records("HTTPS", &[&alias], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn check_svcb_records_mixed_modes() {
        let mut results = Vec::new();
        let target1 = Name::from_str("other.example.com.").unwrap();
        let target2 = Name::from_str("cdn.example.com.").unwrap();
        let alias = SVCB::new(0, target1, vec![]);
        let svc = SVCB::new(1, target2, vec![]);
        check_svcb_records("HTTPS", &[&alias, &svc], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }

    #[test]
    fn check_svcb_records_multiple_aliases() {
        let mut results = Vec::new();
        let target1 = Name::from_str("a.example.com.").unwrap();
        let target2 = Name::from_str("b.example.com.").unwrap();
        let alias1 = SVCB::new(0, target1, vec![]);
        let alias2 = SVCB::new(0, target2, vec![]);
        check_svcb_records("SVCB", &[&alias1, &alias2], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }
}
