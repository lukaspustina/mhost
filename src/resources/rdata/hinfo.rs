// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use serde::Serialize;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct HINFO {
    cpu: String,
    os: String,
}

impl HINFO {
    pub fn new(cpu: String, os: String) -> HINFO {
        HINFO { cpu, os }
    }

    pub fn cpu(&self) -> &str {
        &self.cpu
    }

    pub fn os(&self) -> &str {
        &self.os
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hinfo_new_and_accessors() {
        let hinfo = HINFO::new("Intel".to_string(), "Linux".to_string());
        assert_eq!(hinfo.cpu(), "Intel");
        assert_eq!(hinfo.os(), "Linux");
    }

    #[test]
    fn hinfo_empty_fields() {
        let hinfo = HINFO::new(String::new(), String::new());
        assert_eq!(hinfo.cpu(), "");
        assert_eq!(hinfo.os(), "");
    }
}

#[doc(hidden)]
impl From<hickory_resolver::proto::rr::rdata::HINFO> for HINFO {
    fn from(hinfo: hickory_resolver::proto::rr::rdata::HINFO) -> Self {
        HINFO {
            cpu: String::from_utf8_lossy(hinfo.cpu()).into_owned(),
            os: String::from_utf8_lossy(hinfo.os()).into_owned(),
        }
    }
}
