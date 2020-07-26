use nom::Err;

mod domain_verification;
mod spf;

use crate::Result;
use crate::Error;
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
