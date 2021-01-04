use crate::resources::{RData, RecordType};
use serde::Serialize;
use trust_dns_resolver::Name;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
pub struct Record {
    name: Name,
    rr_type: RecordType,
    ttl: u32,
    rdata: RData,
}

impl Record {
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Name associated with this record. This is either the `Name` of the record or the `Name` the record points to.
    pub fn associated_name(&self) -> &Name {
        match self.rdata {
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
        self.rr_type
    }

    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    pub fn rdata(&self) -> &RData {
        &self.rdata
    }
}

#[doc(hidden)]
impl From<&trust_dns_resolver::proto::rr::Record> for Record {
    fn from(record: &trust_dns_resolver::proto::rr::Record) -> Self {
        Record {
            name: record.name().clone(),
            rr_type: record.rr_type().into(),
            ttl: record.ttl(),
            rdata: record.rdata().clone().into(),
        }
    }
}
