// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Derived from trust-dns by Benjamin Fry <benjaminfry@me.com>
// cf. https://github.com/bluejekyll/trust-dns
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::resources::{RData, RecordType};
use serde::Serialize;
use std::hash::{Hash, Hasher};
use trust_dns_resolver::Name;

#[derive(Debug, Eq, Clone, Serialize)]
pub struct Record {
    name: Name,
    #[serde(rename = "type")]
    record_type: RecordType,
    ttl: u32,
    data: RData,
}

impl PartialEq for Record {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.record_type == other.record_type && self.data == other.data
    }
}

impl Hash for Record {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name().hash(state);
        self.record_type().hash(state);
        // Do not take self.ttl() into account
        self.data().hash(state);
    }
}

impl Record {
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Name associated with this record. This is either the `Name` of the record or the `Name` the record points to.
    pub fn associated_name(&self) -> &Name {
        match self.data {
            RData::A(_) => self.name(),
            RData::AAAA(_) => self.name(),
            RData::ANAME(ref x) => x,
            RData::CAA => self.name(),
            RData::CNAME(ref x) => x,
            RData::MX(ref x) => x.exchange(),
            RData::NAPTR => self.name(),
            RData::NULL(_) => self.name(),
            RData::NS(ref x) => x,
            RData::OPENPGPKEY => self.name(),
            RData::OPT => self.name(),
            RData::PTR(ref x) => x,
            RData::SOA(ref x) => x.mname(),
            RData::SRV(ref x) => x.target(),
            RData::SSHFP => self.name(),
            RData::TLSA => self.name(),
            RData::TXT(_) => self.name(),
            RData::DNSSEC => self.name(),
            RData::Unknown(_) => self.name(),
            RData::ZERO => self.name(),
        }
    }

    pub fn record_type(&self) -> RecordType {
        self.record_type
    }

    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    pub fn data(&self) -> &RData {
        &self.data
    }
}

#[doc(hidden)]
impl From<&trust_dns_resolver::proto::rr::Record> for Record {
    fn from(record: &trust_dns_resolver::proto::rr::Record) -> Self {
        Record {
            name: record.name().clone(),
            record_type: record.rr_type().into(),
            ttl: record.ttl(),
            data: record.rdata().clone().into(),
        }
    }
}
