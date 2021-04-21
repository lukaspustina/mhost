// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Derived from trust-dns by Benjamin Fry <benjaminfry@me.com>
// cf. https://github.com/bluejekyll/trust-dns
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use serde::Serialize;
use trust_dns_resolver::Name;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Serialize)]
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

    pub fn increment_serial(&mut self) {}

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

#[doc(hidden)]
impl From<trust_dns_resolver::proto::rr::rdata::SOA> for SOA {
    fn from(soa: trust_dns_resolver::proto::rr::rdata::SOA) -> Self {
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
