// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use nom::Err;
use nom::error::Error as NomError;

use crate::{Error, Result};

#[derive(Debug, PartialEq)]
pub struct Bimi<'a> {
    version: &'a str,
    logo: Option<&'a str>,
    authority: Option<&'a str>,
}

#[allow(clippy::should_implement_trait)]
impl<'a> Bimi<'a> {
    pub fn from_str(txt: &'a str) -> Result<Bimi<'a>> {
        match parser::bimi(txt) {
            Ok((_, result)) => Ok(result),
            Err(Err::Incomplete(_)) => Err(Error::ParserError {
                what: txt.to_string(),
                to: "BIMI TXT Record",
                why: "input is incomplete".to_string(),
            }),
            Err(Err::Error(NomError { input: what, code: why })) | Err(Err::Failure(NomError { input: what, code: why })) => Err(Error::ParserError {
                what: what.to_string(),
                to: "BIMI TXT Record",
                why: format!("{:?}", why),
            }),
        }
    }

    pub fn version(&self) -> &str {
        self.version
    }

    pub fn logo(&self) -> Option<&str> {
        self.logo
    }

    pub fn authority(&self) -> Option<&str> {
        self.authority
    }
}

pub(crate) mod parser {
    use super::Bimi;
    use crate::resources::rdata::parsed_txt::tag_value;
    use nom::error::{Error as NomError, ErrorKind};
    use nom::{Err, IResult};

    pub fn bimi(input: &str) -> IResult<&str, Bimi<'_>> {
        let (rest, tags) = tag_value::parser::tag_list(input)?;

        // First tag must be v=BIMI1
        let version = tags.first().map(|(k, v)| (*k, *v));
        match version {
            Some(("v", "BIMI1")) => {}
            _ => return Err(Err::Error(NomError::new(input, ErrorKind::Tag))),
        }

        let find = |key: &str| -> Option<&str> {
            tags.iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| *v)
                .and_then(|v| if v.is_empty() { None } else { Some(v) })
        };

        Ok((
            rest,
            Bimi {
                version: "BIMI1",
                logo: find("l"),
                authority: find("a"),
            },
        ))
    }
}

#[cfg(test)]
mod test {
    use super::parser::bimi;
    use super::*;

    #[test]
    fn both_tags() {
        crate::utils::tests::logging::init();
        let record = "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem";

        let (_, result) = bimi(record).expect("failed to parse BIMI record");

        assert_eq!(result.version(), "BIMI1");
        assert_eq!(result.logo(), Some("https://example.com/logo.svg"));
        assert_eq!(result.authority(), Some("https://example.com/cert.pem"));
    }

    #[test]
    fn logo_only() {
        crate::utils::tests::logging::init();
        let record = "v=BIMI1; l=https://example.com/brand.svg";

        let (_, result) = bimi(record).expect("failed to parse BIMI record");

        assert_eq!(result.logo(), Some("https://example.com/brand.svg"));
        assert_eq!(result.authority(), None);
    }

    #[test]
    fn empty_logo() {
        crate::utils::tests::logging::init();
        let record = "v=BIMI1; l=; a=https://example.com/cert.pem";

        let (_, result) = bimi(record).expect("failed to parse BIMI record");

        assert_eq!(result.logo(), None);
        assert_eq!(result.authority(), Some("https://example.com/cert.pem"));
    }

    #[test]
    fn invalid_version() {
        crate::utils::tests::logging::init();
        let record = "v=BIMI2; l=https://example.com/logo.svg";

        let res = bimi(record);

        assert!(res.is_err());
    }
}
