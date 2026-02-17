// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Derived from trust-dns by Benjamin Fry <benjaminfry@me.com>
// cf. https://github.com/bluejekyll/trust-dns
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use hickory_resolver::Name;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct SOA {
    mname: Name,
    rname: Name,
    serial: u32,
    refresh: i32,
    retry: i32,
    expire: i32,
    minimum: u32,
}

impl SOA {
    pub fn new(mname: Name, rname: Name, serial: u32, refresh: i32, retry: i32, expire: i32, minimum: u32) -> Self {
        SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        }
    }

    pub fn mname(&self) -> &Name {
        &self.mname
    }

    pub fn rname(&self) -> &Name {
        &self.rname
    }

    pub fn serial(&self) -> u32 {
        self.serial
    }

    pub fn refresh(&self) -> i32 {
        self.refresh
    }

    pub fn retry(&self) -> i32 {
        self.retry
    }

    pub fn expire(&self) -> i32 {
        self.expire
    }

    pub fn minimum(&self) -> u32 {
        self.minimum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_soa() -> SOA {
        SOA::new(
            Name::from_utf8("ns1.example.com.").unwrap(),
            Name::from_utf8("admin.example.com.").unwrap(),
            2024010101,
            3600,
            900,
            604800,
            86400,
        )
    }

    #[test]
    fn soa_new_and_accessors() {
        let soa = example_soa();
        assert_eq!(soa.mname(), &Name::from_utf8("ns1.example.com.").unwrap());
        assert_eq!(soa.rname(), &Name::from_utf8("admin.example.com.").unwrap());
        assert_eq!(soa.serial(), 2024010101);
        assert_eq!(soa.refresh(), 3600);
        assert_eq!(soa.retry(), 900);
        assert_eq!(soa.expire(), 604800);
        assert_eq!(soa.minimum(), 86400);
    }

    #[test]
    fn soa_negative_timers() {
        let soa = SOA::new(
            Name::from_utf8("ns1.example.com.").unwrap(),
            Name::from_utf8("admin.example.com.").unwrap(),
            1,
            -3600,
            -900,
            -1,
            0,
        );
        assert_eq!(soa.refresh(), -3600);
        assert_eq!(soa.retry(), -900);
        assert_eq!(soa.expire(), -1);
        assert_eq!(soa.minimum(), 0);
    }

    #[test]
    fn soa_equality() {
        let soa1 = example_soa();
        let soa2 = example_soa();
        assert_eq!(soa1, soa2);
    }

    #[test]
    fn soa_inequality_on_serial() {
        let soa1 = example_soa();
        let soa2 = SOA::new(
            Name::from_utf8("ns1.example.com.").unwrap(),
            Name::from_utf8("admin.example.com.").unwrap(),
            2024010102,
            3600,
            900,
            604800,
            86400,
        );
        assert_ne!(soa1, soa2);
    }
}

#[doc(hidden)]
impl From<hickory_resolver::proto::rr::rdata::SOA> for SOA {
    fn from(soa: hickory_resolver::proto::rr::rdata::SOA) -> Self {
        SOA {
            mname: soa.mname().clone(),
            rname: soa.rname().clone(),
            serial: soa.serial(),
            refresh: soa.refresh(),
            retry: soa.retry(),
            expire: soa.expire(),
            minimum: soa.minimum(),
        }
    }
}
