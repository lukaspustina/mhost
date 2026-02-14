// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use nom::Err;
use nom::error::Error as NomError;

mod bimi;
mod dmarc;
mod domain_verification;
mod mta_sts;
mod spf;
pub(crate) mod tag_value;
mod tls_rpt;

use crate::Error;
use crate::Result;
pub use bimi::Bimi;
pub use dmarc::Dmarc;
pub use domain_verification::DomainVerification;
pub use mta_sts::MtaSts;
pub use spf::{Mechanism, Modifier, Qualifier, Spf, Word};
pub use tls_rpt::TlsRpt;

#[derive(Debug)]
pub enum ParsedTxt<'a> {
    Bimi(Bimi<'a>),
    Dmarc(Dmarc<'a>),
    DomainVerification(DomainVerification<'a>),
    MtaSts(MtaSts<'a>),
    Spf(Spf<'a>),
    TlsRpt(TlsRpt<'a>),
}

#[allow(clippy::should_implement_trait)]
impl<'a> ParsedTxt<'a> {
    pub fn from_str(txt: &'a str) -> Result<ParsedTxt<'a>> {
        match parser::parsed_txt(txt) {
            Ok((_, result)) => Ok(result),
            Err(Err::Incomplete(_)) => Err(Error::ParserError {
                what: txt.to_string(),
                to: "ParsedTxt",
                why: "input is incompletely parsed".to_string(),
            }),
            Err(Err::Error(NomError { input: what, code: why })) | Err(Err::Failure(NomError { input: what, code: why })) => Err(Error::ParserError {
                what: what.to_string(),
                to: "ParsedTxt",
                why: format!("{:?}", why),
            }),
        }
    }
}

mod parser {
    use crate::resources::rdata::parsed_txt::{bimi, dmarc, domain_verification, mta_sts, spf, tls_rpt, ParsedTxt};
    use nom::branch::alt;
    use nom::IResult;

    pub fn parsed_txt(input: &str) -> IResult<&str, ParsedTxt<'_>> {
        // DMARC, MTA-STS, TLS-RPT, BIMI must come before domain_verification
        // because v=DMARC1;... could match the generic three-tuple pattern
        let (input, parsed_txt) = alt((dmarc, mta_sts, tls_rpt, bimi, domain_verification, spf))(input)?;

        Ok((input, parsed_txt))
    }

    pub fn dmarc(input: &str) -> IResult<&str, ParsedTxt<'_>> {
        let (input, dmarc) = dmarc::parser::dmarc(input)?;

        Ok((input, ParsedTxt::Dmarc(dmarc)))
    }

    pub fn mta_sts(input: &str) -> IResult<&str, ParsedTxt<'_>> {
        let (input, mta_sts) = mta_sts::parser::mta_sts(input)?;

        Ok((input, ParsedTxt::MtaSts(mta_sts)))
    }

    pub fn tls_rpt(input: &str) -> IResult<&str, ParsedTxt<'_>> {
        let (input, tls_rpt) = tls_rpt::parser::tls_rpt(input)?;

        Ok((input, ParsedTxt::TlsRpt(tls_rpt)))
    }

    pub fn bimi(input: &str) -> IResult<&str, ParsedTxt<'_>> {
        let (input, bimi) = bimi::parser::bimi(input)?;

        Ok((input, ParsedTxt::Bimi(bimi)))
    }

    pub fn spf(input: &str) -> IResult<&str, ParsedTxt<'_>> {
        let (input, spf) = spf::parser::spf(input)?;

        Ok((input, ParsedTxt::Spf(spf)))
    }

    pub fn domain_verification(input: &str) -> IResult<&str, ParsedTxt<'_>> {
        let (input, domain_verification) = domain_verification::parser::domain_verification(input)?;

        Ok((input, ParsedTxt::DomainVerification(domain_verification)))
    }
}
