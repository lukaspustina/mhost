use crate::resources::{RData, RecordType};
use serde::Serialize;
use trust_dns_resolver::Name;

#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct Record {
    pub name_labels: Name,
    pub rr_type: RecordType,
    pub ttl: u32,
    pub rdata: RData,
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
