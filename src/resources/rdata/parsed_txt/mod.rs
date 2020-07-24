use nom::Err;
use thiserror::Error;

mod domain_verification;
mod spf;

pub use domain_verification::DomainVerification;
pub use spf::{Mechanism, Modifier, Qualifier, Spf, Word};

#[derive(Debug, Error)]
pub enum ParserError<'a> {
    #[error("failed to parse {what}")]
    ParserError { what: &'a str, why: String },
}

type Result<'a, T> = std::result::Result<T, ParserError<'a>>;

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
            Err(Err::Incomplete(_)) => Err(ParserError::ParserError {
                what: txt,
                why: "input is incomplete".to_string(),
            }),
            Err(Err::Error((what, why))) | Err(Err::Failure((what, why))) => Err(ParserError::ParserError {
                what,
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
