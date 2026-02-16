use std::cmp::Ordering;

use crate::RecordType;

pub trait Ordinal {
    fn ordinal(&self) -> usize;
}

pub fn order_by_ordinal<T: Ordinal>(left: &T, right: &T) -> Ordering {
    left.ordinal().cmp(&right.ordinal())
}

impl Ordinal for RecordType {
    fn ordinal(&self) -> usize {
        match self {
            RecordType::SOA => 1,
            RecordType::NS => 2,
            RecordType::MX => 3,
            RecordType::TXT => 4,
            RecordType::ANY => 5,
            RecordType::AXFR => 6,
            RecordType::CAA => 7,
            RecordType::IXFR => 8,
            RecordType::NAPTR => 9,
            RecordType::OPENPGPKEY => 10,
            RecordType::OPT => 11,
            RecordType::SSHFP => 12,
            RecordType::TLSA => 13,
            RecordType::DNSKEY => 14,
            RecordType::DS => 15,
            RecordType::RRSIG => 16,
            RecordType::NSEC => 17,
            RecordType::NSEC3 => 18,
            RecordType::NSEC3PARAM => 19,
            RecordType::HINFO => 20,
            RecordType::HTTPS => 21,
            RecordType::SVCB => 22,
            RecordType::ZERO => 23,
            RecordType::CNAME => 24,
            RecordType::A => 25,
            RecordType::AAAA => 26,
            RecordType::ANAME => 27,
            RecordType::PTR => 28,
            RecordType::SRV => 29,
            RecordType::NULL => 30,
            RecordType::Unknown(_) => 31,
        }
    }
}
