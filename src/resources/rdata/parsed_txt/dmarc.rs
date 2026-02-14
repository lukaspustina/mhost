// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use nom::error::Error as NomError;
use nom::Err;

use crate::{Error, Result};

#[derive(Debug, PartialEq)]
pub struct Dmarc<'a> {
    version: &'a str,
    policy: &'a str,
    subdomain_policy: Option<&'a str>,
    rua: Option<&'a str>,
    ruf: Option<&'a str>,
    adkim: Option<&'a str>,
    aspf: Option<&'a str>,
    pct: Option<&'a str>,
    fo: Option<&'a str>,
    ri: Option<&'a str>,
}

#[allow(clippy::should_implement_trait)]
impl<'a> Dmarc<'a> {
    pub fn from_str(txt: &'a str) -> Result<Dmarc<'a>> {
        match parser::dmarc(txt) {
            Ok((_, result)) => Ok(result),
            Err(Err::Incomplete(_)) => Err(Error::ParserError {
                what: txt.to_string(),
                to: "DMARC TXT Record",
                why: "input is incomplete".to_string(),
            }),
            Err(Err::Error(NomError { input: what, code: why }))
            | Err(Err::Failure(NomError { input: what, code: why })) => Err(Error::ParserError {
                what: what.to_string(),
                to: "DMARC TXT Record",
                why: format!("{:?}", why),
            }),
        }
    }

    pub fn version(&self) -> &str {
        self.version
    }

    pub fn policy(&self) -> &str {
        self.policy
    }

    pub fn subdomain_policy(&self) -> Option<&str> {
        self.subdomain_policy
    }

    pub fn rua(&self) -> Option<&str> {
        self.rua
    }

    pub fn ruf(&self) -> Option<&str> {
        self.ruf
    }

    pub fn adkim(&self) -> Option<&str> {
        self.adkim
    }

    pub fn aspf(&self) -> Option<&str> {
        self.aspf
    }

    pub fn pct(&self) -> Option<&str> {
        self.pct
    }

    pub fn fo(&self) -> Option<&str> {
        self.fo
    }

    pub fn ri(&self) -> Option<&str> {
        self.ri
    }
}

pub(crate) mod parser {
    use super::Dmarc;
    use crate::resources::rdata::parsed_txt::tag_value;
    use nom::error::{Error as NomError, ErrorKind};
    use nom::{Err, IResult};

    pub fn dmarc(input: &str) -> IResult<&str, Dmarc<'_>> {
        let (rest, tags) = tag_value::parser::tag_list(input)?;

        // First tag must be v=DMARC1
        let version = tags.first().map(|(k, v)| (*k, *v));
        match version {
            Some(("v", "DMARC1")) => {}
            _ => return Err(Err::Error(NomError::new(input, ErrorKind::Tag))),
        }

        // p= is required
        let policy = tags.iter().find(|(k, _)| *k == "p").map(|(_, v)| *v);
        let policy = match policy {
            Some(p) => p,
            None => return Err(Err::Error(NomError::new(input, ErrorKind::Tag))),
        };

        let find = |key: &str| -> Option<&str> { tags.iter().find(|(k, _)| *k == key).map(|(_, v)| *v) };

        Ok((
            rest,
            Dmarc {
                version: "DMARC1",
                policy,
                subdomain_policy: find("sp"),
                rua: find("rua"),
                ruf: find("ruf"),
                adkim: find("adkim"),
                aspf: find("aspf"),
                pct: find("pct"),
                fo: find("fo"),
                ri: find("ri"),
            },
        ))
    }
}

#[cfg(test)]
mod test {
    use super::parser::dmarc;
    use super::*;

    #[test]
    fn minimal_record() {
        crate::utils::tests::logging::init();
        let record = "v=DMARC1; p=none";

        let (_, result) = dmarc(record).expect("failed to parse DMARC record");

        assert_eq!(result.version(), "DMARC1");
        assert_eq!(result.policy(), "none");
        assert_eq!(result.subdomain_policy(), None);
        assert_eq!(result.rua(), None);
    }

    #[test]
    fn full_record() {
        crate::utils::tests::logging::init();
        let record = "v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com; adkim=s; aspf=r; pct=100; fo=1; ri=86400";

        let (_, result) = dmarc(record).expect("failed to parse DMARC record");

        assert_eq!(result.version(), "DMARC1");
        assert_eq!(result.policy(), "reject");
        assert_eq!(result.subdomain_policy(), Some("quarantine"));
        assert_eq!(result.rua(), Some("mailto:dmarc@example.com"));
        assert_eq!(result.ruf(), Some("mailto:forensic@example.com"));
        assert_eq!(result.adkim(), Some("s"));
        assert_eq!(result.aspf(), Some("r"));
        assert_eq!(result.pct(), Some("100"));
        assert_eq!(result.fo(), Some("1"));
        assert_eq!(result.ri(), Some("86400"));
    }

    #[test]
    fn quarantine_policy() {
        crate::utils::tests::logging::init();
        let record = "v=DMARC1; p=quarantine; rua=mailto:d@example.com";

        let (_, result) = dmarc(record).expect("failed to parse DMARC record");

        assert_eq!(result.policy(), "quarantine");
        assert_eq!(result.rua(), Some("mailto:d@example.com"));
    }

    #[test]
    fn invalid_version() {
        crate::utils::tests::logging::init();
        let record = "v=DMARC2; p=none";

        let res = dmarc(record);

        assert!(res.is_err());
    }

    #[test]
    fn missing_policy() {
        crate::utils::tests::logging::init();
        let record = "v=DMARC1; rua=mailto:d@example.com";

        let res = dmarc(record);

        assert!(res.is_err());
    }
}
