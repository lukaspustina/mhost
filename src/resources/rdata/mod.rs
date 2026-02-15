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
pub use dnssec::{DigestType, DnssecAlgorithm, DNSKEY, DS, NSEC, NSEC3, NSEC3PARAM, RRSIG};
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

#[doc(hidden)]
macro_rules! iana_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident = $val:expr => $display:expr ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Serialize)]
        pub enum $name {
            $( $(#[$vmeta])* $variant, )+
            Unassigned(u8),
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    $( $name::$variant => write!(f, $display), )+
                    $name::Unassigned(v) => write!(f, "Unassigned({})", v),
                }
            }
        }

        impl From<u8> for $name {
            fn from(v: u8) -> Self {
                match v {
                    $( $val => $name::$variant, )+
                    v => $name::Unassigned(v),
                }
            }
        }
    };
}

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

/// DNS record data, with one variant per supported record type.
///
/// Use the typed accessor methods (`.a()`, `.mx()`, `.txt()`, etc.) to extract
/// the inner data for a specific type. Each accessor returns `Option<&T>`,
/// returning `None` if the variant doesn't match.
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
    DNSKEY(DNSKEY),
    DS(DS),
    RRSIG(RRSIG),
    NSEC(NSEC),
    NSEC3(NSEC3),
    NSEC3PARAM(NSEC3PARAM),
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
    accessor!(DNSKEY, dnskey, DNSKEY);
    accessor!(DS, ds, DS);
    accessor!(RRSIG, rrsig, RRSIG);
    accessor!(NSEC, nsec, NSEC);
    accessor!(NSEC3, nsec3, NSEC3);
    accessor!(NSEC3PARAM, nsec3param, NSEC3PARAM);
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
    fn rdata_dnskey_accessor() {
        let dnskey = DNSKEY::new(
            257, 3, DnssecAlgorithm::EcdsaP256Sha256,
            "key_data".to_string(), Some(2371), true, true, false,
        );
        let rdata = RData::DNSKEY(dnskey.clone());
        assert_eq!(rdata.dnskey(), Some(&dnskey));
        assert!(rdata.a().is_none());
    }

    #[test]
    fn rdata_ds_accessor() {
        let ds = DS::new(
            12345, DnssecAlgorithm::RsaSha256, DigestType::Sha256, "ABCDEF".to_string(),
        );
        let rdata = RData::DS(ds.clone());
        assert_eq!(rdata.ds(), Some(&ds));
        assert!(rdata.dnskey().is_none());
    }

    #[test]
    fn rdata_rrsig_accessor() {
        let name = Name::from_str("example.com.").unwrap();
        let rrsig = RRSIG::new(
            "A".to_string(), DnssecAlgorithm::RsaSha256, 2, 300,
            1700000000, 1699000000, 12345, name, "sig".to_string(),
        );
        let rdata = RData::RRSIG(rrsig.clone());
        assert_eq!(rdata.rrsig(), Some(&rrsig));
        assert!(rdata.dnskey().is_none());
    }

    #[test]
    fn rdata_nsec_accessor() {
        let name = Name::from_str("next.example.com.").unwrap();
        let nsec = NSEC::new(name, vec!["A".to_string(), "AAAA".to_string()]);
        let rdata = RData::NSEC(nsec.clone());
        assert_eq!(rdata.nsec(), Some(&nsec));
        assert!(rdata.dnskey().is_none());
    }

    #[test]
    fn rdata_nsec3_accessor() {
        let nsec3 = NSEC3::new(
            "SHA-1".to_string(), false, 10, "ABCDEF".to_string(),
            "HASH".to_string(), vec!["A".to_string()],
        );
        let rdata = RData::NSEC3(nsec3.clone());
        assert_eq!(rdata.nsec3(), Some(&nsec3));
        assert!(rdata.nsec().is_none());
    }

    #[test]
    fn rdata_nsec3param_accessor() {
        let nsec3param = NSEC3PARAM::new("SHA-1".to_string(), false, 10, "salt".to_string());
        let rdata = RData::NSEC3PARAM(nsec3param.clone());
        assert_eq!(rdata.nsec3param(), Some(&nsec3param));
        assert!(rdata.nsec3().is_none());
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
                use hickory_resolver::proto::dnssec::PublicKey as HickoryPublicKey;

                fn nsec3_hash_algorithm_name(algo: hickory_resolver::proto::dnssec::Nsec3HashAlgorithm) -> String {
                    match u8::from(algo) {
                        1 => "SHA-1".to_string(),
                        v => format!("Unknown({})", v),
                    }
                }

                fn hex_or_dash(bytes: &[u8]) -> String {
                    if bytes.is_empty() {
                        "-".to_string()
                    } else {
                        bytes.iter().map(|b| format!("{:02X}", b)).collect()
                    }
                }

                fn convert_sig(sig: &hickory_resolver::proto::dnssec::rdata::SIG) -> RData {
                    let algo_u8: u8 = sig.algorithm().into();
                    RData::RRSIG(RRSIG::new(
                        sig.type_covered().to_string(),
                        algo_u8.into(),
                        sig.num_labels(),
                        sig.original_ttl(),
                        sig.sig_expiration().get(),
                        sig.sig_inception().get(),
                        sig.key_tag(),
                        sig.signer_name().clone(),
                        data_encoding::BASE64.encode(sig.sig()),
                    ))
                }

                match value {
                    TDnssec::DNSKEY(ref key) => {
                        let algo_u8: u8 = key.public_key().algorithm().into();
                        RData::DNSKEY(DNSKEY::new(
                            key.flags(),
                            3,
                            algo_u8.into(),
                            data_encoding::BASE64.encode(key.public_key().public_bytes()),
                            key.calculate_key_tag().ok(),
                            key.zone_key(),
                            key.secure_entry_point(),
                            key.revoke(),
                        ))
                    }
                    TDnssec::CDNSKEY(ref key) => {
                        let algo_u8: u8 = key.algorithm().map(u8::from).unwrap_or(0);
                        let pub_key_b64 = key
                            .public_key()
                            .map(|pk| data_encoding::BASE64.encode(pk.public_bytes()))
                            .unwrap_or_default();
                        RData::DNSKEY(DNSKEY::new(
                            key.flags(),
                            3,
                            algo_u8.into(),
                            pub_key_b64,
                            None,
                            key.zone_key(),
                            key.secure_entry_point(),
                            key.revoke(),
                        ))
                    }
                    TDnssec::KEY(ref key) => {
                        let algo_u8: u8 = key.algorithm().into();
                        RData::DNSKEY(DNSKEY::new(
                            key.flags(),
                            3,
                            algo_u8.into(),
                            data_encoding::BASE64.encode(key.public_key()),
                            None,
                            false,
                            false,
                            key.revoke(),
                        ))
                    }
                    TDnssec::DS(ref ds) => {
                        let algo_u8: u8 = ds.algorithm().into();
                        let digest_u8: u8 = ds.digest_type().into();
                        let digest_hex: String =
                            ds.digest().iter().map(|b| format!("{:02X}", b)).collect();
                        RData::DS(DS::new(ds.key_tag(), algo_u8.into(), digest_u8.into(), digest_hex))
                    }
                    TDnssec::CDS(ref ds) => {
                        let algo_u8: u8 = ds.algorithm().map(u8::from).unwrap_or(0);
                        let digest_u8: u8 = ds.digest_type().into();
                        let digest_hex: String =
                            ds.digest().iter().map(|b| format!("{:02X}", b)).collect();
                        RData::DS(DS::new(ds.key_tag(), algo_u8.into(), digest_u8.into(), digest_hex))
                    }
                    TDnssec::RRSIG(ref sig) => convert_sig(sig),
                    TDnssec::SIG(ref sig) => convert_sig(sig),
                    TDnssec::NSEC(ref nsec) => {
                        let types: Vec<String> = nsec.type_bit_maps().map(|rt| rt.to_string()).collect();
                        RData::NSEC(NSEC::new(nsec.next_domain_name().clone(), types))
                    }
                    TDnssec::NSEC3(ref nsec3) => {
                        let hash_algo = nsec3_hash_algorithm_name(nsec3.hash_algorithm());
                        let salt = hex_or_dash(nsec3.salt());
                        let next_hashed =
                            data_encoding::BASE32HEX_NOPAD.encode(nsec3.next_hashed_owner_name());
                        let types: Vec<String> =
                            nsec3.type_bit_maps().map(|rt| rt.to_string()).collect();
                        RData::NSEC3(NSEC3::new(
                            hash_algo,
                            nsec3.opt_out(),
                            nsec3.iterations(),
                            salt,
                            next_hashed,
                            types,
                        ))
                    }
                    TDnssec::NSEC3PARAM(ref param) => {
                        let hash_algo = nsec3_hash_algorithm_name(param.hash_algorithm());
                        let salt = hex_or_dash(param.salt());
                        RData::NSEC3PARAM(NSEC3PARAM::new(
                            hash_algo,
                            param.opt_out(),
                            param.iterations(),
                            salt,
                        ))
                    }
                    _ => RData::Unknown(UNKNOWN::new(0, NULL::new())),
                }
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
