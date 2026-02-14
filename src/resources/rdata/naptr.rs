// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use serde::Serialize;
use hickory_resolver::Name;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct NAPTR {
    order: u16,
    preference: u16,
    flags: String,
    services: String,
    regexp: String,
    replacement: Name,
}

impl NAPTR {
    pub fn new(
        order: u16,
        preference: u16,
        flags: String,
        services: String,
        regexp: String,
        replacement: Name,
    ) -> NAPTR {
        NAPTR {
            order,
            preference,
            flags,
            services,
            regexp,
            replacement,
        }
    }

    pub fn order(&self) -> u16 {
        self.order
    }

    pub fn preference(&self) -> u16 {
        self.preference
    }

    pub fn flags(&self) -> &str {
        &self.flags
    }

    pub fn services(&self) -> &str {
        &self.services
    }

    pub fn regexp(&self) -> &str {
        &self.regexp
    }

    pub fn replacement(&self) -> &Name {
        &self.replacement
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn naptr_new_and_accessors() {
        let replacement = Name::from_str("sip.example.com.").unwrap();
        let naptr = NAPTR::new(
            100,
            10,
            "u".to_string(),
            "E2U+sip".to_string(),
            "!^.*$!sip:info@example.com!".to_string(),
            replacement.clone(),
        );
        assert_eq!(naptr.order(), 100);
        assert_eq!(naptr.preference(), 10);
        assert_eq!(naptr.flags(), "u");
        assert_eq!(naptr.services(), "E2U+sip");
        assert_eq!(naptr.regexp(), "!^.*$!sip:info@example.com!");
        assert_eq!(naptr.replacement(), &replacement);
    }
}

#[doc(hidden)]
impl From<hickory_resolver::proto::rr::rdata::NAPTR> for NAPTR {
    fn from(naptr: hickory_resolver::proto::rr::rdata::NAPTR) -> Self {
        NAPTR {
            order: naptr.order(),
            preference: naptr.preference(),
            flags: String::from_utf8_lossy(naptr.flags()).into_owned(),
            services: String::from_utf8_lossy(naptr.services()).into_owned(),
            regexp: String::from_utf8_lossy(naptr.regexp()).into_owned(),
            replacement: naptr.replacement().clone(),
        }
    }
}
