// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Derived from trust-dns by Benjamin Fry <benjaminfry@me.com>
// cf. https://github.com/bluejekyll/trust-dns
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Serialize;

pub use caa::CAA;
pub use dnssec::DNSSEC;
pub use hickory_resolver::{IntoName, Name};
pub use hinfo::HINFO;
pub use mx::MX;
pub use naptr::NAPTR;
pub use null::NULL;
pub use openpgpkey::OPENPGPKEY;
pub use soa::SOA;
pub use srv::SRV;
pub use sshfp::SSHFP;
pub use svcb::SVCB;
pub use tlsa::{CertUsage, Matching, Selector, TLSA};
pub use txt::TXT;
pub use unknown::UNKNOWN;

mod caa;
mod dnssec;
mod hinfo;
mod mx;
mod naptr;
mod null;
mod openpgpkey;
pub mod parsed_txt;
mod soa;
mod srv;
mod sshfp;
mod svcb;
mod tlsa;
mod txt;
mod unknown;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
#[allow(clippy::upper_case_acronyms)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    ANAME(Name),
    CAA(CAA),
    CNAME(Name),
    HINFO(HINFO),
    HTTPS(SVCB),
    MX(MX),
    NAPTR(NAPTR),
    NULL(NULL),
    NS(Name),
    OPENPGPKEY(OPENPGPKEY),
    // OPT is a pseudo-record for EDNS0 extension mechanism, not a regular DNS record
    OPT,
    PTR(Name),
    SOA(SOA),
    SRV(SRV),
    SSHFP(SSHFP),
    SVCB(SVCB),
    TLSA(TLSA),
    TXT(TXT),
    DNSSEC(DNSSEC),
    Unknown(UNKNOWN),
    ZERO,
}

macro_rules! accessor {
    ($variant:ident, $method:ident, $out_type:ty) => {
        pub fn $method(&self) -> Option<&$out_type> {
            match self {
                RData::$variant(ref inner) => Some(inner),
                _ => None,
            }
        }
    };
}

impl RData {
    accessor!(A, a, Ipv4Addr);
    accessor!(AAAA, aaaa, Ipv6Addr);
    accessor!(ANAME, aname, Name);
    accessor!(CAA, caa, CAA);
    accessor!(CNAME, cname, Name);
    accessor!(HINFO, hinfo, HINFO);
    accessor!(HTTPS, https, SVCB);
    accessor!(MX, mx, MX);
    accessor!(NAPTR, naptr, NAPTR);
    accessor!(NULL, null, NULL);
    accessor!(NS, ns, Name);
    accessor!(OPENPGPKEY, openpgpkey, OPENPGPKEY);
    accessor!(PTR, ptr, Name);
    accessor!(SOA, soa, SOA);
    accessor!(SRV, srv, SRV);
    accessor!(SSHFP, sshfp, SSHFP);
    accessor!(SVCB, svcb, SVCB);
    accessor!(TLSA, tlsa, TLSA);
    accessor!(TXT, txt, TXT);
    accessor!(DNSSEC, dnssec, DNSSEC);
    accessor!(Unknown, unknown, UNKNOWN);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn rdata_a_accessor() {
        let rdata = RData::A(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(rdata.a(), Some(&Ipv4Addr::new(1, 2, 3, 4)));
        assert!(rdata.aaaa().is_none());
        assert!(rdata.mx().is_none());
    }

    #[test]
    fn rdata_aaaa_accessor() {
        let rdata = RData::AAAA(Ipv6Addr::LOCALHOST);
        assert_eq!(rdata.aaaa(), Some(&Ipv6Addr::LOCALHOST));
        assert!(rdata.a().is_none());
    }

    #[test]
    fn rdata_cname_accessor() {
        let name = Name::from_str("example.com.").unwrap();
        let rdata = RData::CNAME(name.clone());
        assert_eq!(rdata.cname(), Some(&name));
        assert!(rdata.a().is_none());
    }

    #[test]
    fn rdata_caa_accessor() {
        let caa = CAA::new(true, "issue".to_string(), "ca.example.com".to_string());
        let rdata = RData::CAA(caa.clone());
        assert_eq!(rdata.caa(), Some(&caa));
        assert!(rdata.tlsa().is_none());
    }

    #[test]
    fn rdata_hinfo_accessor() {
        let hinfo = HINFO::new("CPU".to_string(), "OS".to_string());
        let rdata = RData::HINFO(hinfo.clone());
        assert_eq!(rdata.hinfo(), Some(&hinfo));
        assert!(rdata.a().is_none());
    }

    #[test]
    fn rdata_https_accessor() {
        let target = Name::from_str("cdn.example.com.").unwrap();
        let svcb_data = SVCB::new(1, target, vec![]);
        let rdata = RData::HTTPS(svcb_data.clone());
        assert_eq!(rdata.https(), Some(&svcb_data));
        assert!(rdata.svcb().is_none());
    }

    #[test]
    fn rdata_svcb_accessor() {
        let target = Name::from_str("svc.example.com.").unwrap();
        let svcb_data = SVCB::new(1, target, vec![]);
        let rdata = RData::SVCB(svcb_data.clone());
        assert_eq!(rdata.svcb(), Some(&svcb_data));
        assert!(rdata.https().is_none());
    }

    #[test]
    fn rdata_naptr_accessor() {
        let replacement = Name::from_str("sip.example.com.").unwrap();
        let naptr = NAPTR::new(100, 10, "u".to_string(), "sip".to_string(), "".to_string(), replacement);
        let rdata = RData::NAPTR(naptr.clone());
        assert_eq!(rdata.naptr(), Some(&naptr));
        assert!(rdata.srv().is_none());
    }

    #[test]
    fn rdata_sshfp_accessor() {
        use sshfp::{Algorithm, FingerprintType};
        let sshfp_data = SSHFP::new(Algorithm::RSA, FingerprintType::SHA256, vec![0xaa]);
        let rdata = RData::SSHFP(sshfp_data.clone());
        assert_eq!(rdata.sshfp(), Some(&sshfp_data));
        assert!(rdata.tlsa().is_none());
    }

    #[test]
    fn rdata_tlsa_accessor() {
        use tlsa::{CertUsage, Matching, Selector};
        let tlsa_data = TLSA::new(CertUsage::DaneEe, Selector::Full, Matching::Sha256, vec![0x01]);
        let rdata = RData::TLSA(tlsa_data.clone());
        assert_eq!(rdata.tlsa(), Some(&tlsa_data));
        assert!(rdata.sshfp().is_none());
    }

    #[test]
    fn rdata_openpgpkey_accessor() {
        let key = OPENPGPKEY::new(vec![0x01, 0x02]);
        let rdata = RData::OPENPGPKEY(key.clone());
        assert_eq!(rdata.openpgpkey(), Some(&key));
        assert!(rdata.a().is_none());
    }

    #[test]
    fn rdata_dnssec_accessor() {
        let dnssec = DNSSEC::new("DNSKEY".to_string(), "key data".to_string());
        let rdata = RData::DNSSEC(dnssec.clone());
        assert_eq!(rdata.dnssec(), Some(&dnssec));
        assert!(rdata.a().is_none());
    }
}

#[doc(hidden)]
#[allow(unused_variables, deprecated)]
impl From<hickory_resolver::proto::rr::RData> for RData {
    fn from(rdata: hickory_resolver::proto::rr::RData) -> Self {
        use hickory_resolver::proto::rr::RData as TRData;

        match rdata {
            TRData::A(value) => RData::A(value.0),
            TRData::AAAA(value) => RData::AAAA(value.0),
            TRData::ANAME(value) => RData::ANAME(value.0),
            TRData::CAA(value) => RData::CAA(value.into()),
            TRData::CNAME(value) => RData::CNAME(value.0),
            TRData::HINFO(value) => RData::HINFO(value.into()),
            TRData::HTTPS(value) => RData::HTTPS(SVCB::from_hickory_svcb(&value)),
            TRData::MX(value) => RData::MX(value.into()),
            TRData::NAPTR(value) => RData::NAPTR(value.into()),
            TRData::NULL(value) => RData::NULL(value.into()),
            TRData::NS(value) => RData::NS(value.0),
            TRData::OPENPGPKEY(value) => RData::OPENPGPKEY(value.into()),
            TRData::OPT(value) => RData::OPT,
            TRData::PTR(value) => RData::PTR(value.0),
            TRData::SOA(value) => RData::SOA(value.into()),
            TRData::SRV(value) => RData::SRV(value.into()),
            TRData::SSHFP(value) => RData::SSHFP(value.into()),
            TRData::SVCB(value) => RData::SVCB(value.into()),
            TRData::TLSA(value) => RData::TLSA(value.into()),
            TRData::TXT(value) => RData::TXT(value.into()),
            TRData::DNSSEC(value) => {
                use hickory_resolver::proto::dnssec::rdata::DNSSECRData as TDnssec;
                let sub_type = match &value {
                    TDnssec::DNSKEY(_) => "DNSKEY",
                    TDnssec::DS(_) => "DS",
                    TDnssec::RRSIG(_) => "RRSIG",
                    TDnssec::SIG(_) => "SIG",
                    TDnssec::KEY(_) => "KEY",
                    TDnssec::NSEC(_) => "NSEC",
                    TDnssec::NSEC3(_) => "NSEC3",
                    TDnssec::NSEC3PARAM(_) => "NSEC3PARAM",
                    TDnssec::CDNSKEY(_) => "CDNSKEY",
                    TDnssec::CDS(_) => "CDS",
                    TDnssec::TSIG(_) => "TSIG",
                    TDnssec::Unknown { .. } => "Unknown",
                    _ => "Unknown",
                }
                .to_string();
                let description = format!("{}", value);
                RData::DNSSEC(DNSSEC::new(sub_type, description))
            }
            TRData::Unknown { code, rdata } => {
                let code_u16: u16 = code.into();
                RData::Unknown(UNKNOWN::new(code_u16, rdata.into()))
            }
            TRData::ZERO => RData::ZERO,
            // Catch any other new variants we don't handle
            _ => RData::Unknown(UNKNOWN::new(0, NULL::new())),
        }
    }
}
