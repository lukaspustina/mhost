use nom::Err;
use thiserror::Error;

mod spf;
pub use spf::{Mechanism, Modifier, Qualifier, Spf, Word};

#[derive(Debug, Error)]
pub enum ParserError<'a> {
    #[error("failed to parse {what}")]
    ParserError { what: &'a str, why: String },
}

type Result<'a, T> = std::result::Result<T, ParserError<'a>>;

#[derive(Debug)]
pub enum ParsedTxt<'a> {
    Spf(Spf<'a>)
}

#[allow(clippy::should_implement_trait)]
impl<'a> ParsedTxt<'a> {
    pub fn from_str(txt: &'a str) -> Result<ParsedTxt<'a>> {
        match parser::parsed_txt(txt) {
            Ok((_, spf)) => Ok(spf),
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
    use nom::IResult;
    use crate::resources::rdata::parsed_txt::ParsedTxt;
    use nom::branch::alt;
    use crate::resources::rdata::parsed_txt::spf;

    pub fn parsed_txt(input: &str) -> IResult<&str, ParsedTxt> {
        let (input, parsed_txt) = alt((
            spf,
            spf,
        ))(input)?;

        Ok((input, parsed_txt))
    }

    pub fn spf(input: &str) -> IResult<&str, ParsedTxt> {
        let (input, spf) = spf::parser::spf(input)?;

        Ok((input, ParsedTxt::Spf(spf)))
    }
}