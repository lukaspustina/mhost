// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use hickory_resolver::Name;
use serde::Serialize;

/// Shared data type for both SVCB and HTTPS record types (RFC 9460).
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct SVCB {
    svc_priority: u16,
    target_name: Name,
    svc_params: Vec<SvcParam>,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
pub struct SvcParam {
    key: String,
    value: String,
}

impl SVCB {
    pub fn new(svc_priority: u16, target_name: Name, svc_params: Vec<SvcParam>) -> SVCB {
        SVCB {
            svc_priority,
            target_name,
            svc_params,
        }
    }

    pub fn svc_priority(&self) -> u16 {
        self.svc_priority
    }

    pub fn target_name(&self) -> &Name {
        &self.target_name
    }

    pub fn svc_params(&self) -> &[SvcParam] {
        &self.svc_params
    }

    /// Returns true if this is an alias form (priority 0).
    pub fn is_alias(&self) -> bool {
        self.svc_priority == 0
    }

    #[doc(hidden)]
    pub fn from_hickory_svcb(svcb: &hickory_resolver::proto::rr::rdata::SVCB) -> Self {
        let svc_params = svcb
            .svc_params()
            .iter()
            .map(|(key, value)| SvcParam {
                key: key.to_string(),
                value: value.to_string(),
            })
            .collect();

        SVCB {
            svc_priority: svcb.svc_priority(),
            target_name: svcb.target_name().clone(),
            svc_params,
        }
    }
}

impl SvcParam {
    pub fn new(key: String, value: String) -> SvcParam {
        SvcParam { key, value }
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn svcb_new_and_accessors() {
        let target = Name::from_str("cdn.example.com.").unwrap();
        let params = vec![SvcParam::new("alpn".to_string(), "h2".to_string())];
        let svcb = SVCB::new(1, target.clone(), params);
        assert_eq!(svcb.svc_priority(), 1);
        assert_eq!(svcb.target_name(), &target);
        assert_eq!(svcb.svc_params().len(), 1);
        assert_eq!(svcb.svc_params()[0].key(), "alpn");
        assert_eq!(svcb.svc_params()[0].value(), "h2");
    }

    #[test]
    fn svcb_is_alias() {
        let target = Name::from_str("example.com.").unwrap();
        let alias = SVCB::new(0, target.clone(), vec![]);
        assert!(alias.is_alias());

        let service = SVCB::new(1, target, vec![]);
        assert!(!service.is_alias());
    }

    #[test]
    fn svc_param_new_and_accessors() {
        let param = SvcParam::new("port".to_string(), "443".to_string());
        assert_eq!(param.key(), "port");
        assert_eq!(param.value(), "443");
    }
}

#[doc(hidden)]
impl From<hickory_resolver::proto::rr::rdata::SVCB> for SVCB {
    fn from(svcb: hickory_resolver::proto::rr::rdata::SVCB) -> Self {
        let svc_params = svcb
            .svc_params()
            .iter()
            .map(|(key, value)| SvcParam {
                key: key.to_string(),
                value: value.to_string(),
            })
            .collect();

        SVCB {
            svc_priority: svcb.svc_priority(),
            target_name: svcb.target_name().clone(),
            svc_params,
        }
    }
}
