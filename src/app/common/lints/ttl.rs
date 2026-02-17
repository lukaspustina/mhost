use super::CheckResult;
use crate::resolver::lookup::Uniquify;
use crate::resolver::Lookups;
use crate::resources::{Record, RecordType};

const MIN_TTL: u32 = 60;
const MAX_NS_MX_TTL: u32 = 604_800; // 1 week
const MAX_SOA_MINIMUM: u32 = 86_400; // 1 day

/// Run TTL sanity lint checks against the given lookups.
pub fn check_ttl(lookups: &Lookups) -> Vec<CheckResult> {
    let records: Vec<&Record> = lookups.records();
    let mut results = Vec::new();
    check_low_ttls(&records, &mut results);
    check_high_ns_mx_ttls(&records, &mut results);
    check_soa_minimum_ttl(lookups, &mut results);
    results
}

fn check_low_ttls(records: &[&Record], results: &mut Vec<CheckResult>) {
    let low_ttl_records: Vec<String> = records
        .iter()
        .filter(|r| r.ttl() < MIN_TTL && r.ttl() > 0)
        .map(|r| format!("{} ({}s, {:?})", r.name(), r.ttl(), r.record_type()))
        .collect();

    if low_ttl_records.is_empty() {
        results.push(CheckResult::Ok(format!("No records with TTL below {}s", MIN_TTL)));
    } else {
        results.push(CheckResult::Warning(format!(
            "Records with very low TTL (<{}s): {}. This causes excessive query load",
            MIN_TTL,
            low_ttl_records.join(", ")
        )));
    }
}

fn check_high_ns_mx_ttls(records: &[&Record], results: &mut Vec<CheckResult>) {
    let high_ttl_records: Vec<String> = records
        .iter()
        .filter(|r| (r.record_type() == RecordType::NS || r.record_type() == RecordType::MX) && r.ttl() > MAX_NS_MX_TTL)
        .map(|r| format!("{} ({}s, {:?})", r.name(), r.ttl(), r.record_type()))
        .collect();

    if high_ttl_records.is_empty() {
        results.push(CheckResult::Ok(
            "No NS/MX records with excessively high TTL".to_string(),
        ));
    } else {
        results.push(CheckResult::Warning(format!(
            "NS/MX records with TTL over 1 week: {}. This makes DNS migrations dangerously slow",
            high_ttl_records.join(", ")
        )));
    }
}

fn check_soa_minimum_ttl(lookups: &Lookups, results: &mut Vec<CheckResult>) {
    let unique_soa = lookups.soa().unique();
    let soa_records: Vec<_> = unique_soa.iter().collect();
    for soa in &soa_records {
        if soa.minimum() > MAX_SOA_MINIMUM {
            results.push(CheckResult::Warning(format!(
                "SOA minimum TTL is {}s (>{} day): high negative caching TTL can delay propagation of new records",
                soa.minimum(),
                MAX_SOA_MINIMUM / 86_400
            )));
            return;
        }
    }
    if !soa_records.is_empty() {
        results.push(CheckResult::Ok(
            "SOA minimum TTL is within reasonable range".to_string(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_low_ttls_all_ok() {
        let records: Vec<&Record> = vec![];
        let mut results = Vec::new();
        check_low_ttls(&records, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn check_high_ns_mx_ttls_ok() {
        let records: Vec<&Record> = vec![];
        let mut results = Vec::new();
        check_high_ns_mx_ttls(&records, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn check_soa_minimum_ok() {
        let lookups = Lookups::empty();
        let mut results = Vec::new();
        check_soa_minimum_ttl(&lookups, &mut results);
        assert!(results.is_empty()); // No SOA records to check
    }
}
