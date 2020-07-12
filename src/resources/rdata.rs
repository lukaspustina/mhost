use std::net::{Ipv4Addr, Ipv6Addr};
use trust_dns_resolver::proto::rr::dnssec::rdata::DNSSECRData;
use trust_dns_resolver::proto::rr::rdata::{CAA, MX, NAPTR, NULL, OPENPGPKEY, OPT, SOA, SRV, SSHFP, TLSA, TXT};
use trust_dns_resolver::Name;

#[derive(Debug, PartialEq, Clone, Eq)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    ANAME(Name),
    CAA(CAA),
    CNAME(Name),
    MX(MX),
    NAPTR(NAPTR),
    NULL(NULL),
    NS(Name),
    OPENPGPKEY(OPENPGPKEY),
    OPT(OPT),
    PTR(Name),
    SOA(SOA),
    SRV(SRV),
    SSHFP(SSHFP),
    TLSA(TLSA),
    TXT(TXT),
    DNSSEC(DNSSECRData),
    Unknown { code: u16, rdata: NULL },
    ZERO,
}

#[doc(hidden)]
impl From<trust_dns_resolver::proto::rr::RData> for RData {
    fn from(rdata: trust_dns_resolver::proto::rr::RData) -> Self {
        use trust_dns_resolver::proto::rr::RData as TRData;

        match rdata {
            TRData::A(value) => RData::A(value),
            TRData::AAAA(value) => RData::AAAA(value),
            TRData::ANAME(value) => RData::ANAME(value),
            TRData::CAA(value) => RData::CAA(value),
            TRData::CNAME(value) => RData::CNAME(value),
            TRData::MX(value) => RData::MX(value),
            TRData::NAPTR(value) => RData::NAPTR(value),
            TRData::NULL(value) => RData::NULL(value),
            TRData::NS(value) => RData::NS(value),
            TRData::OPENPGPKEY(value) => RData::OPENPGPKEY(value),
            TRData::OPT(value) => RData::OPT(value),
            TRData::PTR(value) => RData::PTR(value),
            TRData::SOA(value) => RData::SOA(value),
            TRData::SRV(value) => RData::SRV(value),
            TRData::SSHFP(value) => RData::SSHFP(value),
            TRData::TLSA(value) => RData::TLSA(value),
            TRData::TXT(value) => RData::TXT(value),
            TRData::DNSSEC(value) => RData::DNSSEC(value),
            TRData::Unknown { code, rdata } => RData::Unknown { code, rdata },
            TRData::ZERO => RData::ZERO,
        }
    }
}
