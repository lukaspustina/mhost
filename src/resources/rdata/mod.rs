use serde::Serialize;
use std::net::{Ipv4Addr, Ipv6Addr};
use trust_dns_resolver::Name;

mod mx;
pub use mx::MX;
mod null;
pub use null::NULL;
mod soa;
pub use soa::SOA;
mod srv;
pub use srv::SRV;
mod txt;
pub use txt::TXT;

#[derive(Debug, PartialEq, Clone, Eq, Serialize)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    ANAME(Name),
    // TODO: CAA(CAA),
    CAA,
    CNAME(Name),
    MX(MX),
    // TODO: NAPTR(NAPTR),
    NAPTR,
    NULL(NULL),
    NS(Name),
    // TODO: OPENPGPKEY(OPENPGPKEY),
    OPENPGPKEY,
    // TODO: OPT(OPT),
    OPT,
    PTR(Name),
    SOA(SOA),
    SRV(SRV),
    // TODO: SSHFP(SSHFP),
    SSHFP,
    // TODO: TLSA(TLSA),
    TLSA,
    TXT(TXT),
    // TODO: DNSSEC(DNSSECRData),
    DNSSEC,
    Unknown { code: u16, rdata: NULL },
    ZERO,
}

#[doc(hidden)]
#[allow(unused_variables)]
impl From<trust_dns_resolver::proto::rr::RData> for RData {
    fn from(rdata: trust_dns_resolver::proto::rr::RData) -> Self {
        use trust_dns_resolver::proto::rr::RData as TRData;

        match rdata {
            TRData::A(value) => RData::A(value),
            TRData::AAAA(value) => RData::AAAA(value),
            TRData::ANAME(value) => RData::ANAME(value),
            TRData::CAA(value) => RData::CAA,
            TRData::CNAME(value) => RData::CNAME(value),
            TRData::MX(value) => RData::MX(value.into()),
            TRData::NAPTR(value) => RData::NAPTR,
            TRData::NULL(value) => RData::NULL(value.into()),
            TRData::NS(value) => RData::NS(value),
            TRData::OPENPGPKEY(value) => RData::OPENPGPKEY,
            TRData::OPT(value) => RData::OPT,
            TRData::PTR(value) => RData::PTR(value),
            TRData::SOA(value) => RData::SOA(value.into()),
            TRData::SRV(value) => RData::SRV(value.into()),
            TRData::SSHFP(value) => RData::SSHFP,
            TRData::TLSA(value) => RData::TLSA,
            TRData::TXT(value) => RData::TXT(value.into()),
            TRData::DNSSEC(value) => RData::DNSSEC,
            TRData::Unknown { code, rdata } => RData::Unknown {
                code,
                rdata: rdata.into(),
            },
            TRData::ZERO => RData::ZERO,
        }
    }
}
