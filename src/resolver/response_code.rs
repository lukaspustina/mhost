// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! DNS response codes.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The response code (RCODE) a nameserver answered with, cf. RFC 1035 and RFC 2136.
///
/// Serialises as its mnemonic, e.g. `"NXDOMAIN"`; codes without one as `"RCODE<n>"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResponseCode {
    NoError,
    FormErr,
    ServFail,
    NXDomain,
    NotImp,
    Refused,
    YXDomain,
    YXRRSet,
    NXRRSet,
    NotAuth,
    NotZone,
    Unknown(u16),
}

impl From<u16> for ResponseCode {
    fn from(code: u16) -> Self {
        match code {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormErr,
            2 => ResponseCode::ServFail,
            3 => ResponseCode::NXDomain,
            4 => ResponseCode::NotImp,
            5 => ResponseCode::Refused,
            6 => ResponseCode::YXDomain,
            7 => ResponseCode::YXRRSet,
            8 => ResponseCode::NXRRSet,
            9 => ResponseCode::NotAuth,
            10 => ResponseCode::NotZone,
            code => ResponseCode::Unknown(code),
        }
    }
}

impl From<ResponseCode> for u16 {
    fn from(code: ResponseCode) -> u16 {
        match code {
            ResponseCode::NoError => 0,
            ResponseCode::FormErr => 1,
            ResponseCode::ServFail => 2,
            ResponseCode::NXDomain => 3,
            ResponseCode::NotImp => 4,
            ResponseCode::Refused => 5,
            ResponseCode::YXDomain => 6,
            ResponseCode::YXRRSet => 7,
            ResponseCode::NXRRSet => 8,
            ResponseCode::NotAuth => 9,
            ResponseCode::NotZone => 10,
            ResponseCode::Unknown(code) => code,
        }
    }
}

impl ResponseCode {
    pub(crate) fn from_proto(code: hickory_resolver::proto::op::ResponseCode) -> Self {
        u16::from(code).into()
    }
}

impl fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mnemonic = match self {
            ResponseCode::NoError => "NOERROR",
            ResponseCode::FormErr => "FORMERR",
            ResponseCode::ServFail => "SERVFAIL",
            ResponseCode::NXDomain => "NXDOMAIN",
            ResponseCode::NotImp => "NOTIMP",
            ResponseCode::Refused => "REFUSED",
            ResponseCode::YXDomain => "YXDOMAIN",
            ResponseCode::YXRRSet => "YXRRSET",
            ResponseCode::NXRRSet => "NXRRSET",
            ResponseCode::NotAuth => "NOTAUTH",
            ResponseCode::NotZone => "NOTZONE",
            ResponseCode::Unknown(code) => return write!(f, "RCODE{}", code),
        };
        f.write_str(mnemonic)
    }
}

impl FromStr for ResponseCode {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = match s {
            "NOERROR" => ResponseCode::NoError,
            "FORMERR" => ResponseCode::FormErr,
            "SERVFAIL" => ResponseCode::ServFail,
            "NXDOMAIN" => ResponseCode::NXDomain,
            "NOTIMP" => ResponseCode::NotImp,
            "REFUSED" => ResponseCode::Refused,
            "YXDOMAIN" => ResponseCode::YXDomain,
            "YXRRSET" => ResponseCode::YXRRSet,
            "NXRRSET" => ResponseCode::NXRRSet,
            "NOTAUTH" => ResponseCode::NotAuth,
            "NOTZONE" => ResponseCode::NotZone,
            other => match other.strip_prefix("RCODE").map(u16::from_str) {
                Some(Ok(code)) => ResponseCode::from(code),
                _ => {
                    return Err(crate::Error::ParserError {
                        what: s.to_string(),
                        to: "ResponseCode",
                        why: "unknown response code".to_string(),
                    })
                }
            },
        };
        Ok(code)
    }
}

impl Serialize for ResponseCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ResponseCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        ResponseCode::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn string_round_trip() {
        for code in [
            ResponseCode::NoError,
            ResponseCode::FormErr,
            ResponseCode::ServFail,
            ResponseCode::NXDomain,
            ResponseCode::NotImp,
            ResponseCode::Refused,
            ResponseCode::YXDomain,
            ResponseCode::YXRRSet,
            ResponseCode::NXRRSet,
            ResponseCode::NotAuth,
            ResponseCode::NotZone,
            ResponseCode::Unknown(23),
        ] {
            assert_eq!(ResponseCode::from_str(&code.to_string()).unwrap(), code, "{code}");
        }
        assert_eq!(ResponseCode::ServFail.to_string(), "SERVFAIL");
        assert_eq!(ResponseCode::Unknown(23).to_string(), "RCODE23");
        assert!(ResponseCode::from_str("BOGUS").is_err());
    }

    #[test]
    fn from_wire_code() {
        assert_eq!(ResponseCode::from(3), ResponseCode::NXDomain);
        assert_eq!(ResponseCode::from(0), ResponseCode::NoError);
        assert_eq!(ResponseCode::from(16), ResponseCode::Unknown(16));
        assert_eq!(u16::from(ResponseCode::Refused), 5);
    }
}
