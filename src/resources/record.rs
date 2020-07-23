use crate::resources::{RData, RecordType};
use serde::Serialize;
use trust_dns_resolver::Name;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
pub struct Record {
    name_labels: Name,
    rr_type: RecordType,
    ttl: u32,
    rdata: RData,
}

impl Record {
    pub fn name_labels(&self) -> &Name {
        &self.name_labels
    }

    pub fn rr_type(&self) -> RecordType {
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
            name_labels: record.name().clone(),
            rr_type: record.rr_type().into(),
            ttl: record.ttl(),
            rdata: record.rdata().clone().into(),
        }
    }
}
