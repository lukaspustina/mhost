use nom::Err;

use crate::resources::rdata::parsed_txt::{ParserError, Result};

#[derive(Debug, PartialEq)]
pub struct DomainVerification<'a> {
    verifier: &'a str,
    scope: &'a str,
    id: &'a str,
}

#[allow(clippy::should_implement_trait)]
impl<'a> DomainVerification<'a> {
    pub fn from_str(txt: &'a str) -> Result<DomainVerification<'a>> {
        match parser::domain_verification(txt) {
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

    pub fn verifier(&self) -> &str {
        self.verifier
    }

    pub fn scope(&self) -> &str {
        self.scope
    }

    pub fn id(&self) -> &str {
        self.id
    }
}


pub(crate) mod parser {
    use super::DomainVerification;
    use nom::error::ErrorKind;
    use nom::{Err, IResult};

    pub fn domain_verification(input: &str) -> IResult<&str, DomainVerification> {
        let left = input.find("=").unwrap_or(0);
        let parts: Vec<&str> = (&input[..left]).rsplitn(3, "-").collect();
        match parts.as_slice() {
            &[_, scope, verifier] => {
                let id = &input[left+1..];
                Ok(("", DomainVerification { verifier, scope, id }))
            }
            _ => Err(Err::Failure((input, ErrorKind::ParseTo))),
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn google() {
            // https://en.wikipedia.org/wiki/TXT_record#Example_usage
            let record = "google-site-verification=6P08Ow5E-8Q0m6vQ7FMAqAYIDprkVV8fUf_7hZ4Qvc8";

            let expected = DomainVerification {
                verifier: "google",
                scope: "site",
                id: "6P08Ow5E-8Q0m6vQ7FMAqAYIDprkVV8fUf_7hZ4Qvc8",
            };

            let (_, result) = domain_verification(record).expect("failed to parse domain verification record");

            assert_eq!(result, expected);
        }


        #[test]
        fn some_page() {
            let record = "some-page-domain-verification=zguxndlw863b";

            let expected = DomainVerification {
                verifier: "some-page",
                scope: "domain",
                id: "zguxndlw863b",
            };

            let (_, result) = domain_verification(record).expect("failed to parse domain verification record");

            assert_eq!(result, expected);
        }
    }
}
