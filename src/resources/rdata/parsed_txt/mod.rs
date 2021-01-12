// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use nom::Err;

mod domain_verification;
mod spf;

use crate::Error;
use crate::Result;
pub use domain_verification::DomainVerification;
pub use spf::{Mechanism, Modifier, Qualifier, Spf, Word};

#[derive(Debug)]
pub enum ParsedTxt<'a> {
    DomainVerification(DomainVerification<'a>),
    Spf(Spf<'a>),
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
            Err(Err::Error((what, why))) | Err(Err::Failure((what, why))) => Err(Error::ParserError {
                what: what.to_string(),
                to: "ParsedTxt",
                why: why.description().to_string(),
            }),
        }
    }
}

mod parser {
    use crate::resources::rdata::parsed_txt::{domain_verification, spf, ParsedTxt};
    use nom::branch::alt;
    use nom::IResult;

    pub fn parsed_txt(input: &str) -> IResult<&str, ParsedTxt> {
        let (input, parsed_txt) = alt((domain_verification, spf))(input)?;

        Ok((input, parsed_txt))
    }

    pub fn spf(input: &str) -> IResult<&str, ParsedTxt> {
        let (input, spf) = spf::parser::spf(input)?;

        Ok((input, ParsedTxt::Spf(spf)))
    }

    pub fn domain_verification(input: &str) -> IResult<&str, ParsedTxt> {
        let (input, domain_verification) = domain_verification::parser::domain_verification(input)?;

        Ok((input, ParsedTxt::DomainVerification(domain_verification)))
    }
}
