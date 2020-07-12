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
