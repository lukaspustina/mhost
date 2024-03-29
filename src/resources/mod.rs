// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Resources like records and record types that are used to communicate queries and results.
//!
//! This is mostly a copy of the trust-dns' types in order to gain more control. Please see [Trust-DNS RR module](http://trust-dns.org/target/doc/trust_dns/rr/index.html)
//!

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub use rdata::RData;
pub use record::Record;
pub use record_type::RecordType;

use crate::{Error, Name, Result};
use smallvec::SmallVec;
use std::num::ParseIntError;

pub mod rdata;
pub mod record;
pub mod record_type;

pub trait NameToIpAddr {
    fn to_ip_addr(&self) -> Result<IpAddr>;

    fn to_ip_addr_string(&self) -> String {
        self.to_ip_addr()
            .map(|x| x.to_string())
            .unwrap_or_else(|_| "-".to_string())
    }
}

impl NameToIpAddr for Name {
    /// Converts a PTR-Name into an IP-Addr
    ///
    /// Example:
    /// ```
    /// # use mhost::Name;
    /// # use mhost::IntoName;
    /// # use std::net::Ipv4Addr;
    /// # use mhost::resources::NameToIpAddr;
    /// let ptr_name: Name = "109.101.168.192.in-addr.arpa.".into_name().unwrap();
    /// let ip_addr = ptr_name.to_ip_addr().unwrap();
    /// assert_eq!(ip_addr, Ipv4Addr::new(192, 168, 101, 109));
    /// ```
    #[allow(clippy::many_single_char_names)]
    fn to_ip_addr(&self) -> Result<IpAddr> {
        let str = self.to_string();
        let err = || Error::ParserError {
            what: str.clone(),
            to: "IpAddr",
            why: "is not a ptr name".to_string(),
        };

        if str.ends_with(".in-addr.arpa.") {
            // IPv4
            let ip = &str.as_str()[..str.len() - 14];
            let elements: SmallVec<[std::result::Result<u8, ParseIntError>; 4]> =
                ip.splitn(4, '.').map(str::parse::<u8>).collect();
            let octets: std::result::Result<SmallVec<[u8; 4]>, _> = elements.into_iter().collect();
            let mut octets = octets.map_err(|_| err())?;
            octets.reverse();
            match *octets.as_slice() {
                [a, b, c, d] => Ok(IpAddr::V4(Ipv4Addr::new(a, b, c, d))),
                _ => Err(err()),
            }
        } else if str.ends_with(".ip6.arpa.") {
            // IPv6
            let ip = &str.as_str()[..str.len() - 10];
            let elements: SmallVec<[&str; 32]> = ip.split('.').collect();
            let nibble: SmallVec<[std::result::Result<u8, ParseIntError>; 32]> =
                elements.into_iter().map(|x| u8::from_str_radix(x, 16)).collect();
            let nibble: std::result::Result<SmallVec<[u8; 32]>, _> = nibble.into_iter().collect();
            let mut nibble = nibble.map_err(|_| err())?;
            nibble.reverse();
            let octets: SmallVec<[u8; 16]> = nibble
                .as_slice()
                .chunks_exact(2)
                // The modulo protects us from "attempt to multiply with overflow" and "attempt to add with overflow" in case a value larger than 16 sneaks in.
                // This does not happen with valid ipv6 address, but may happen in invalid input -- cf. `tests::fuzz*`
                .map(|byte| byte[0] % 16 * 16 + byte[1] % 16)
                .collect();

            match *octets.as_slice() {
                [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p] => Ok(IpAddr::V6(Ipv6Addr::from([
                    a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p,
                ]))),
                _ => Err(err()),
            }
        } else {
            Err(err())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use spectral::prelude::*;

    use crate::IntoName;

    use super::*;

    #[test]
    fn test_192_168_101_1() {
        crate::utils::tests::logging::init();
        let ip_expected = Ipv4Addr::new(192, 168, 101, 1);
        let name: Name = ip_expected.into_name().unwrap();

        let ip = name.to_ip_addr();

        assert_that(&ip).is_ok().is_equal_to(IpAddr::from(ip_expected));
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_2a0a_a955_bef6__ad7_fad3_c233_2c() {
        crate::utils::tests::logging::init();
        let ip_expected = Ipv6Addr::from_str("2a0a:a955:bef6::ad7:fad3:c233:2c").unwrap();
        let name: Name = ip_expected.into_name().unwrap();

        let ip = name.to_ip_addr();

        assert_that(&ip).is_ok().is_equal_to(IpAddr::from(ip_expected));
    }

    #[test]
    #[allow(non_snake_case)]
    fn fuzz_a_a_aB_ip6_arpa_() {
        crate::utils::tests::logging::init();
        // This is not a valid ipv6 address
        let name: Name = "a.a.aB.ip6.arpa.".into_name().unwrap();

        // This will fail to parse but should not panic
        let ip = name.to_ip_addr();

        assert_that(&ip).is_err();
    }

    #[test]
    #[allow(non_snake_case)]
    fn fuzz_a_a_aa_a_ip6_arpa_() {
        crate::utils::tests::logging::init();
        // This is not a valid ipv6 address
        let name: Name = "a.a.aa.a.ip6.arpa.".into_name().unwrap();

        // This will fail to parse but should not panic
        let ip = name.to_ip_addr();

        assert_that(&ip).is_err();
    }
}
