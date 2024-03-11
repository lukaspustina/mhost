// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use nom::Err;

use crate::{Error, Result};

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
            Err(Err::Incomplete(_)) => Err(Error::ParserError {
                what: txt.to_string(),
                to: "DomainVerification TXT Record",
                why: "input is incomplete".to_string(),
            }),
            Err(Err::Error((what, why))) | Err(Err::Failure((what, why))) => Err(Error::ParserError {
                what: what.to_string(),
                to: "DomainVerification TXT Record",
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
    use nom::branch::alt;
    use nom::bytes::complete::tag;
    use nom::character::complete::{alphanumeric1, not_line_ending};
    use nom::error::ErrorKind;
    use nom::{Err, IResult};

    pub fn domain_verification(input: &str) -> IResult<&str, DomainVerification> {
        alt((three_tuple_with_id, ms_office_365, zoom))(input)
    }

    fn three_tuple_with_id(input: &str) -> IResult<&str, DomainVerification> {
        let left = input.find('=').unwrap_or(0);
        let parts: Vec<&str> = (input[..left]).rsplitn(3, '-').collect();
        match *parts.as_slice() {
            [_, scope, verifier] => {
                let id = &input[left + 1..];
                Ok(("", DomainVerification { verifier, scope, id }))
            }
            _ => Err(Err::Error((input, ErrorKind::ParseTo))),
        }
    }

    // https://docs.microsoft.com/en-us/microsoft-365/admin/get-help-with-domains/create-dns-records-at-any-dns-hosting-provider?view=o365-worldwide#bkmk_verify
    fn ms_office_365(input: &str) -> IResult<&str, DomainVerification> {
        let (input, _) = tag("MS=")(input)?;
        let (input, id) = alphanumeric1(input)?;

        Ok((
            input,
            DomainVerification {
                verifier: "Microsoft Office 365",
                scope: "domain",
                id,
            },
        ))
    }

    // https://support.zoom.us/hc/en-us/articles/203395207-Associated-domains
    fn zoom(input: &str) -> IResult<&str, DomainVerification> {
        let (input, _) = tag("ZOOM_verify_")(input)?;
        let (input, id) = not_line_ending(input)?;

        Ok((
            input,
            DomainVerification {
                verifier: "Zoom",
                scope: "domain",
                id,
            },
        ))
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn google() {
            crate::utils::tests::logging::init();
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
            crate::utils::tests::logging::init();
            let record = "some-page-domain-verification=zguxndlw863b";

            let expected = DomainVerification {
                verifier: "some-page",
                scope: "domain",
                id: "zguxndlw863b",
            };

            let (_, result) = domain_verification(record).expect("failed to parse domain verification record");

            assert_eq!(result, expected);
        }

        #[test]
        fn microsoft_office_365() {
            crate::utils::tests::logging::init();
            let record = "MS=ms86874996";

            let expected = DomainVerification {
                verifier: "Microsoft Office 365",
                scope: "domain",
                id: "ms86874996",
            };

            let (_, result) = domain_verification(record).expect("failed to parse domain verification record");

            assert_eq!(result, expected);
        }

        #[test]
        fn zoom() {
            crate::utils::tests::logging::init();
            let record = "ZOOM_verify_-JDnDhrHAeeegADdwefC-Q";

            let expected = DomainVerification {
                verifier: "Zoom",
                scope: "domain",
                id: "-JDnDhrHAeeegADdwefC-Q",
            };

            let (_, result) = domain_verification(record).expect("failed to parse domain verification record");

            assert_eq!(result, expected);
        }
    }
}
