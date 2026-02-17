use super::CheckResult;
use crate::resolver::Lookups;
use crate::Name;

/// Run synchronous CNAME apex lint check against the given lookups.
pub fn check_cname_apex(lookups: &Lookups) -> Vec<CheckResult> {
    let mut results = Vec::new();
    let is_apex = !lookups.soa().is_empty();
    if is_apex {
        if lookups.cname().is_empty() {
            results.push(CheckResult::Ok("Apex zone without CNAME".to_string()));
        } else {
            results.push(CheckResult::Failed(
                "Apex zone with CNAME: apex zones must not have CNAME records; cf. RFC 1034, section 3.6.2".to_string(),
            ));
        }
    } else {
        results.push(CheckResult::Ok("Not apex zone".to_string()));
    }
    results
}

pub(crate) fn classify_chain_depth(origin: &Name, depth: usize) -> Vec<CheckResult> {
    if depth <= 3 {
        vec![CheckResult::Ok(format!(
            "CNAME chain from {} has acceptable depth of {}",
            origin, depth
        ))]
    } else {
        vec![CheckResult::Warning(format!(
            "CNAME chain from {} has depth {}: deep chains increase latency and fragility",
            origin, depth
        ))]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn chain_depth_1_is_ok() {
        let results = classify_chain_depth(&name("example.com."), 1);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn chain_depth_3_is_ok() {
        let results = classify_chain_depth(&name("example.com."), 3);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn chain_depth_4_is_warning() {
        let results = classify_chain_depth(&name("example.com."), 4);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
        if let CheckResult::Warning(msg) = &results[0] {
            assert!(msg.contains("depth 4"));
            assert!(msg.contains("latency"));
        }
    }

    #[test]
    fn chain_depth_10_is_warning() {
        let results = classify_chain_depth(&name("example.com."), 10);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
        if let CheckResult::Warning(msg) = &results[0] {
            assert!(msg.contains("depth 10"));
        }
    }
}
