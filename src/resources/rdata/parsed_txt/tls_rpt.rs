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
pub struct TlsRpt<'a> {
    version: &'a str,
    rua: &'a str,
}

#[allow(clippy::should_implement_trait)]
impl<'a> TlsRpt<'a> {
    pub fn from_str(txt: &'a str) -> Result<TlsRpt<'a>> {
        match parser::tls_rpt(txt) {
            Ok((_, result)) => Ok(result),
            Err(Err::Incomplete(_)) => Err(Error::ParserError {
                what: txt.to_string(),
                to: "TLS-RPT TXT Record",
                why: "input is incomplete".to_string(),
            }),
            Err(Err::Error(NomError { input: what, code: why }))
            | Err(Err::Failure(NomError { input: what, code: why })) => Err(Error::ParserError {
                what: what.to_string(),
                to: "TLS-RPT TXT Record",
                why: format!("{:?}", why),
            }),
        }
    }

    pub fn version(&self) -> &str {
        self.version
    }

    pub fn rua(&self) -> &str {
        self.rua
    }
}

pub(crate) mod parser {
    use super::TlsRpt;
    use crate::resources::rdata::parsed_txt::tag_value;
    use nom::error::{Error as NomError, ErrorKind};
    use nom::{Err, IResult};

    pub fn tls_rpt(input: &str) -> IResult<&str, TlsRpt<'_>> {
        let (rest, tags) = tag_value::parser::tag_list(input)?;

        // First tag must be v=TLSRPTv1
        let version = tags.first().map(|(k, v)| (*k, *v));
        match version {
            Some(("v", "TLSRPTv1")) => {}
            _ => return Err(Err::Error(NomError::new(input, ErrorKind::Tag))),
        }

        // rua= is required
        let rua = tags.iter().find(|(k, _)| *k == "rua").map(|(_, v)| *v);
        let rua = match rua {
            Some(rua) => rua,
            None => return Err(Err::Error(NomError::new(input, ErrorKind::Tag))),
        };

        Ok((
            rest,
            TlsRpt {
                version: "TLSRPTv1",
                rua,
            },
        ))
    }
}

#[cfg(test)]
mod test {
    use super::parser::tls_rpt;

    #[test]
    fn mailto_uri() {
        crate::utils::tests::logging::init();
        let record = "v=TLSRPTv1; rua=mailto:tlsrpt@example.com";

        let (_, result) = tls_rpt(record).expect("failed to parse TLS-RPT record");

        assert_eq!(result.version(), "TLSRPTv1");
        assert_eq!(result.rua(), "mailto:tlsrpt@example.com");
    }

    #[test]
    fn https_uri() {
        crate::utils::tests::logging::init();
        let record = "v=TLSRPTv1; rua=https://tlsrpt.example.com/report";

        let (_, result) = tls_rpt(record).expect("failed to parse TLS-RPT record");

        assert_eq!(result.version(), "TLSRPTv1");
        assert_eq!(result.rua(), "https://tlsrpt.example.com/report");
    }

    #[test]
    fn invalid_version() {
        crate::utils::tests::logging::init();
        let record = "v=TLSRPTv2; rua=mailto:t@example.com";

        let res = tls_rpt(record);

        assert!(res.is_err());
    }

    #[test]
    fn missing_rua() {
        crate::utils::tests::logging::init();
        let record = "v=TLSRPTv1";

        let res = tls_rpt(record);

        assert!(res.is_err());
    }
}
