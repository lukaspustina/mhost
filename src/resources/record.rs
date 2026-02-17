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
use hickory_resolver::Name;
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

/// A DNS resource record with name, type, TTL, and record data.
///
/// Equality and hashing ignore the TTL field, so two records with different TTLs
/// but the same name, type, and data are considered equal.
#[derive(Debug, Eq, Clone, Serialize, Deserialize)]
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
            RData::CAA(_) => self.name(),
            RData::CNAME(ref x) => x,
            RData::HINFO(_) => self.name(),
            RData::HTTPS(ref x) => x.target_name(),
            RData::MX(ref x) => x.exchange(),
            RData::NAPTR(ref x) => x.replacement(),
            RData::NULL(_) => self.name(),
            RData::NS(ref x) => x,
            RData::OPENPGPKEY(_) => self.name(),
            RData::OPT => self.name(),
            RData::PTR(ref x) => x,
            RData::SOA(ref x) => x.mname(),
            RData::SRV(ref x) => x.target(),
            RData::SSHFP(_) => self.name(),
            RData::SVCB(ref x) => x.target_name(),
            RData::TLSA(_) => self.name(),
            RData::TXT(_) => self.name(),
            RData::DNSKEY(_) => self.name(),
            RData::DS(_) => self.name(),
            RData::RRSIG(_) => self.name(),
            RData::NSEC(_) => self.name(),
            RData::NSEC3(_) => self.name(),
            RData::NSEC3PARAM(_) => self.name(),
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

#[cfg(test)]
impl Record {
    pub fn new_for_test(name: Name, record_type: RecordType, ttl: u32, data: RData) -> Record {
        Record {
            name,
            record_type,
            ttl,
            data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::rdata::{MX, SOA, SRV, SVCB};
    use std::collections::HashSet;
    use std::net::Ipv4Addr;

    fn name(s: &str) -> Name {
        Name::from_utf8(s).unwrap()
    }

    #[test]
    fn equality_ignores_ttl() {
        let r1 = Record::new_for_test(
            name("example.com."),
            RecordType::A,
            300,
            RData::A(Ipv4Addr::new(1, 2, 3, 4)),
        );
        let r2 = Record::new_for_test(
            name("example.com."),
            RecordType::A,
            3600,
            RData::A(Ipv4Addr::new(1, 2, 3, 4)),
        );
        assert_eq!(r1, r2);
    }

    #[test]
    fn inequality_on_different_data() {
        let r1 = Record::new_for_test(
            name("example.com."),
            RecordType::A,
            300,
            RData::A(Ipv4Addr::new(1, 2, 3, 4)),
        );
        let r2 = Record::new_for_test(
            name("example.com."),
            RecordType::A,
            300,
            RData::A(Ipv4Addr::new(5, 6, 7, 8)),
        );
        assert_ne!(r1, r2);
    }

    #[test]
    fn inequality_on_different_name() {
        let r1 = Record::new_for_test(
            name("a.example.com."),
            RecordType::A,
            300,
            RData::A(Ipv4Addr::new(1, 2, 3, 4)),
        );
        let r2 = Record::new_for_test(
            name("b.example.com."),
            RecordType::A,
            300,
            RData::A(Ipv4Addr::new(1, 2, 3, 4)),
        );
        assert_ne!(r1, r2);
    }

    #[test]
    fn hash_ignores_ttl() {
        let r1 = Record::new_for_test(
            name("example.com."),
            RecordType::A,
            300,
            RData::A(Ipv4Addr::new(1, 2, 3, 4)),
        );
        let r2 = Record::new_for_test(
            name("example.com."),
            RecordType::A,
            9999,
            RData::A(Ipv4Addr::new(1, 2, 3, 4)),
        );
        let mut set = HashSet::new();
        set.insert(r1);
        // r2 differs only in TTL, so it should be found in the set
        assert!(set.contains(&r2));
    }

    #[test]
    fn hash_distinguishes_different_data() {
        let r1 = Record::new_for_test(
            name("example.com."),
            RecordType::A,
            300,
            RData::A(Ipv4Addr::new(1, 2, 3, 4)),
        );
        let r2 = Record::new_for_test(
            name("example.com."),
            RecordType::A,
            300,
            RData::A(Ipv4Addr::new(5, 6, 7, 8)),
        );
        let mut set = HashSet::new();
        set.insert(r1);
        assert!(!set.contains(&r2));
    }

    #[test]
    fn associated_name_a_returns_record_name() {
        let r = Record::new_for_test(
            name("example.com."),
            RecordType::A,
            300,
            RData::A(Ipv4Addr::new(1, 2, 3, 4)),
        );
        assert_eq!(r.associated_name(), &name("example.com."));
    }

    #[test]
    fn associated_name_cname_returns_target() {
        let target = name("target.example.com.");
        let r = Record::new_for_test(
            name("alias.example.com."),
            RecordType::CNAME,
            300,
            RData::CNAME(target.clone()),
        );
        assert_eq!(r.associated_name(), &target);
    }

    #[test]
    fn associated_name_mx_returns_exchange() {
        let exchange = name("mail.example.com.");
        let r = Record::new_for_test(
            name("example.com."),
            RecordType::MX,
            300,
            RData::MX(MX::new(10, exchange.clone())),
        );
        assert_eq!(r.associated_name(), &exchange);
    }

    #[test]
    fn associated_name_ns_returns_nameserver() {
        let ns = name("ns1.example.com.");
        let r = Record::new_for_test(
            name("example.com."),
            RecordType::NS,
            300,
            RData::NS(ns.clone()),
        );
        assert_eq!(r.associated_name(), &ns);
    }

    #[test]
    fn associated_name_ptr_returns_target() {
        let target = name("host.example.com.");
        let r = Record::new_for_test(
            name("4.3.2.1.in-addr.arpa."),
            RecordType::PTR,
            300,
            RData::PTR(target.clone()),
        );
        assert_eq!(r.associated_name(), &target);
    }

    #[test]
    fn associated_name_srv_returns_target() {
        let target = name("server.example.com.");
        let r = Record::new_for_test(
            name("_http._tcp.example.com."),
            RecordType::SRV,
            300,
            RData::SRV(SRV::new(1, 1, 80, target.clone())),
        );
        assert_eq!(r.associated_name(), &target);
    }

    #[test]
    fn associated_name_soa_returns_mname() {
        let mname = name("ns1.example.com.");
        let r = Record::new_for_test(
            name("example.com."),
            RecordType::SOA,
            300,
            RData::SOA(SOA::new(mname.clone(), name("admin.example.com."), 1, 3600, 900, 604800, 86400)),
        );
        assert_eq!(r.associated_name(), &mname);
    }

    #[test]
    fn associated_name_https_returns_target_name() {
        let target = name("cdn.example.com.");
        let r = Record::new_for_test(
            name("example.com."),
            RecordType::HTTPS,
            300,
            RData::HTTPS(SVCB::new(1, target.clone(), vec![])),
        );
        assert_eq!(r.associated_name(), &target);
    }
}

#[doc(hidden)]
impl From<&hickory_resolver::proto::rr::Record> for Record {
    fn from(record: &hickory_resolver::proto::rr::Record) -> Self {
        Record {
            name: record.name().clone(),
            record_type: record.record_type().into(),
            ttl: record.ttl(),
            data: record.data().clone().into(),
        }
    }
}
