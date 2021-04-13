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

pub use mx::MX;
pub use null::NULL;
pub use soa::SOA;
pub use srv::SRV;
pub use trust_dns_resolver::{IntoName, Name};
pub use txt::TXT;
pub use unknown::UNKNOWN;

mod mx;
mod null;
pub mod parsed_txt;
mod soa;
mod srv;
mod txt;
mod unknown;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    ANAME(Name),
    // TODO: CAA(CAA),
    CAA,
    CNAME(Name),
    // TODO: HINFO(HINFO),
    HINFO,
    // TODO: HTTPS(SVCB),
    HTTPS,
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
    // SVCB(SVCB),
    SVCB,
    // TODO: TLSA(TLSA),
    TLSA,
    TXT(TXT),
    // TODO: DNSSEC(DNSSECRData),
    DNSSEC,
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
    accessor!(CNAME, cname, Name);
    accessor!(MX, mx, MX);
    accessor!(NULL, null, NULL);
    accessor!(NS, ns, Name);
    accessor!(PTR, ptr, Name);
    accessor!(SOA, soa, SOA);
    accessor!(SRV, srv, SRV);
    accessor!(TXT, txt, TXT);
    accessor!(Unknown, unknown, UNKNOWN);
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
            TRData::HINFO(value) => RData::HINFO,
            TRData::HTTPS(value) => RData::HTTPS,
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
            TRData::SVCB(value) => RData::SVCB,
            TRData::TLSA(value) => RData::TLSA,
            TRData::TXT(value) => RData::TXT(value.into()),
            TRData::DNSSEC(value) => RData::DNSSEC,
            TRData::Unknown { code, rdata } => RData::Unknown((code, rdata).into()),
            TRData::ZERO => RData::ZERO,
        }
    }
}
