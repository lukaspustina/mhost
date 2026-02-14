// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use serde::Serialize;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct CAA {
    issuer_critical: bool,
    tag: String,
    value: String,
}

impl CAA {
    pub fn new(issuer_critical: bool, tag: String, value: String) -> CAA {
        CAA {
            issuer_critical,
            tag,
            value,
        }
    }

    pub fn issuer_critical(&self) -> bool {
        self.issuer_critical
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

#[doc(hidden)]
impl From<hickory_resolver::proto::rr::rdata::CAA> for CAA {
    fn from(caa: hickory_resolver::proto::rr::rdata::CAA) -> Self {
        let tag = caa.tag().to_string();
        let value = String::from_utf8_lossy(caa.raw_value()).into_owned();

        CAA {
            issuer_critical: caa.issuer_critical(),
            tag,
            value,
        }
    }
}
