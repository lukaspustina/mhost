use crate::{Error, Result};

use serde::Serialize;
use std::fmt;
use std::str::FromStr;
use trust_dns_resolver::proto::rr::dnssec::rdata::DNSSECRecordType;

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
#[allow(dead_code)]
#[derive(Serialize)]
pub enum RecordType {
    A,
    AAAA,
    ANAME,
    ANY,
    AXFR,
    CAA,
    CNAME,
    IXFR,
    MX,
    NAPTR,
    NS,
    NULL,
    OPENPGPKEY,
    OPT,
    PTR,
    SOA,
    SRV,
    SSHFP,
    TLSA,
    TXT,
    // TODO: DNSSEC(DNSSECRecordType),
    DNSSEC,
    Unknown(u16),
    ZERO,
}

impl RecordType {
    #[inline]
    pub fn is_any(self) -> bool {
        self == RecordType::ANY
    }

    #[inline]
    pub fn is_cname(self) -> bool {
        self == RecordType::CNAME
    }

    #[inline]
    pub fn is_srv(self) -> bool {
        self == RecordType::SRV
    }

    #[inline]
    pub fn is_ip_addr(self) -> bool {
        match self {
            RecordType::A | RecordType::AAAA => true,
            _ => false,
        }
    }
}

#[doc(hidden)]
impl From<RecordType> for trust_dns_resolver::proto::rr::RecordType {
    fn from(rt: RecordType) -> Self {
        use trust_dns_resolver::proto::rr::RecordType as Trt;

        match rt {
            RecordType::A => Trt::A,
            RecordType::AAAA => Trt::AAAA,
            RecordType::ANAME => Trt::ANAME,
            RecordType::ANY => Trt::ANY,
            RecordType::AXFR => Trt::AXFR,
            RecordType::CAA => Trt::CAA,
            RecordType::CNAME => Trt::CNAME,
            RecordType::IXFR => Trt::IXFR,
            RecordType::MX => Trt::MX,
            RecordType::NAPTR => Trt::NAPTR,
            RecordType::NS => Trt::NS,
            RecordType::NULL => Trt::NULL,
            RecordType::OPENPGPKEY => Trt::OPENPGPKEY,
            RecordType::OPT => Trt::OPT,
            RecordType::PTR => Trt::PTR,
            RecordType::SOA => Trt::SOA,
            RecordType::SRV => Trt::SRV,
            RecordType::SSHFP => Trt::SSHFP,
            RecordType::TLSA => Trt::TLSA,
            RecordType::TXT => Trt::TXT,
            // TODO: RecordType::DNSSEC(dnssec_rt) => Trt::DNSSEC(dnssec_rt),
            RecordType::DNSSEC => Trt::DNSSEC(DNSSECRecordType::Unknown(0)),
            RecordType::Unknown(value) => Trt::Unknown(value),
            RecordType::ZERO => Trt::ZERO,
        }
    }
}

#[doc(hidden)]
impl From<trust_dns_resolver::proto::rr::RecordType> for RecordType {
    fn from(rt: trust_dns_resolver::proto::rr::RecordType) -> Self {
        use trust_dns_resolver::proto::rr::RecordType as Trt;

        match rt {
            Trt::A => RecordType::A,
            Trt::AAAA => RecordType::AAAA,
            Trt::ANAME => RecordType::ANAME,
            Trt::ANY => RecordType::ANY,
            Trt::AXFR => RecordType::AXFR,
            Trt::CAA => RecordType::CAA,
            Trt::CNAME => RecordType::CNAME,
            Trt::IXFR => RecordType::IXFR,
            Trt::MX => RecordType::MX,
            Trt::NAPTR => RecordType::NAPTR,
            Trt::NS => RecordType::NS,
            Trt::NULL => RecordType::NULL,
            Trt::OPENPGPKEY => RecordType::OPENPGPKEY,
            Trt::OPT => RecordType::OPT,
            Trt::PTR => RecordType::PTR,
            Trt::SOA => RecordType::SOA,
            Trt::SRV => RecordType::SRV,
            Trt::SSHFP => RecordType::SSHFP,
            Trt::TLSA => RecordType::TLSA,
            Trt::TXT => RecordType::TXT,
            // TODO: Trt::DNSSEC(dnssec_rt) => RecordType::DNSSEC(dnssec_rt),
            Trt::DNSSEC(_) => RecordType::DNSSEC,
            Trt::Unknown(value) => RecordType::Unknown(value),
            Trt::ZERO => RecordType::ZERO,
        }
    }
}

impl FromStr for RecordType {
    type Err = Error;

    fn from_str(str: &str) -> Result<Self> {
        match str {
            "A" => Ok(RecordType::A),
            "AAAA" => Ok(RecordType::AAAA),
            "ANAME" => Ok(RecordType::ANAME),
            "CAA" => Ok(RecordType::CAA),
            "CNAME" => Ok(RecordType::CNAME),
            "NULL" => Ok(RecordType::NULL),
            "MX" => Ok(RecordType::MX),
            "NAPTR" => Ok(RecordType::NAPTR),
            "NS" => Ok(RecordType::NS),
            "OPENPGPKEY" => Ok(RecordType::OPENPGPKEY),
            "PTR" => Ok(RecordType::PTR),
            "SOA" => Ok(RecordType::SOA),
            "SRV" => Ok(RecordType::SRV),
            "SSHFP" => Ok(RecordType::SSHFP),
            "TLSA" => Ok(RecordType::TLSA),
            "TXT" => Ok(RecordType::TXT),
            "ANY" | "*" => Ok(RecordType::ANY),
            "AXFR" => Ok(RecordType::AXFR),
            "DNSKEY" | "DS" | "KEY" | "NSEC" | "NSEC3" | "NSEC3PARAM" | "RRSIG" | "SIG" => {
                // TODO: Ok(RecordType::DNSSEC(str.parse()?))
                Ok(RecordType::DNSSEC)
            }
            _ => Err(Error::ParserError {
                what: str.to_string(),
                to: "RecordType",
            }),
        }
    }
}

impl From<RecordType> for &'static str {
    fn from(rt: RecordType) -> &'static str {
        match rt {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::ANAME => "ANAME",
            RecordType::ANY => "ANY",
            RecordType::AXFR => "AXFR",
            RecordType::CAA => "CAA",
            RecordType::CNAME => "CNAME",
            RecordType::ZERO => "",
            RecordType::IXFR => "IXFR",
            RecordType::MX => "MX",
            RecordType::NAPTR => "NAPTR",
            RecordType::NS => "NS",
            RecordType::NULL => "NULL",
            RecordType::OPENPGPKEY => "OPENPGPKEY",
            RecordType::OPT => "OPT",
            RecordType::PTR => "PTR",
            RecordType::SOA => "SOA",
            RecordType::SRV => "SRV",
            RecordType::SSHFP => "SSHFP",
            RecordType::TLSA => "TLSA",
            RecordType::TXT => "TXT",
            // TODO: RecordType::DNSSEC(rt) => rt.into(),
            RecordType::DNSSEC => "DNSSEC",
            RecordType::Unknown(_) => "Unknown",
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(Into::<&str>::into(*self))
    }
}
