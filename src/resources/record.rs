use crate::resources::{RData, RecordType};
use trust_dns_resolver::Name;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Record {
    name_labels: Name,
    rr_type: RecordType,
    ttl: u32,
    rdata: RData,
}
