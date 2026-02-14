// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Shared parser for semicolon-separated tag=value pairs used by DMARC, MTA-STS, TLS-RPT, BIMI, etc.

pub(crate) mod parser {
    use nom::bytes::complete::{tag, take_while};
    use nom::character::complete::space0;
    use nom::combinator::opt;
    use nom::multi::many0;
    use nom::sequence::preceded;
    use nom::IResult;

    /// Parse a single tag name (alphanumeric + underscore)
    fn tag_name(input: &str) -> IResult<&str, &str> {
        take_while(|c: char| c.is_alphanumeric() || c == '_')(input)
    }

    /// Parse a tag value (everything until `;` or end of input)
    fn tag_value(input: &str) -> IResult<&str, &str> {
        take_while(|c: char| c != ';')(input)
    }

    /// Parse a single `key=value` pair
    fn tag_pair(input: &str) -> IResult<&str, (&str, &str)> {
        let (input, name) = tag_name(input)?;
        let (input, _) = tag("=")(input)?;
        let (input, value) = tag_value(input)?;

        Ok((input, (name.trim(), value.trim())))
    }

    /// Parse an additional `; key=value` pair (with surrounding whitespace)
    fn separator_and_pair(input: &str) -> IResult<&str, (&str, &str)> {
        let (input, _) = space0(input)?;
        let (input, _) = tag(";")(input)?;
        let (input, _) = space0(input)?;
        // After a semicolon, we might be at end of input (trailing semicolon)
        if input.is_empty() || !input.contains('=') {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Tag,
            )));
        }
        tag_pair(input)
    }

    /// Parse a full tag list: `key=value; key=value; ...`
    ///
    /// Handles whitespace around `;` separators and optional trailing semicolons.
    pub fn tag_list(input: &str) -> IResult<&str, Vec<(&str, &str)>> {
        let (input, _) = space0(input)?;
        let (input, first) = tag_pair(input)?;
        let (input, rest) = many0(separator_and_pair)(input)?;
        // consume optional trailing semicolon and whitespace
        let (input, _) = space0(input)?;
        let (input, _) = opt(preceded(tag(";"), space0))(input)?;

        let mut result = vec![first];
        result.extend(rest);
        Ok((input, result))
    }
}

#[cfg(test)]
mod test {
    use super::parser::tag_list;

    #[test]
    fn simple_pair() {
        crate::utils::tests::logging::init();
        let (rest, tags) = tag_list("v=DMARC1; p=none").unwrap();
        assert!(rest.is_empty());
        assert_eq!(tags, vec![("v", "DMARC1"), ("p", "none")]);
    }

    #[test]
    fn no_spaces() {
        crate::utils::tests::logging::init();
        let (rest, tags) = tag_list("v=DMARC1;p=none").unwrap();
        assert!(rest.is_empty());
        assert_eq!(tags, vec![("v", "DMARC1"), ("p", "none")]);
    }

    #[test]
    fn extra_spaces() {
        crate::utils::tests::logging::init();
        let (rest, tags) = tag_list("v=DMARC1 ;  p=none ;  rua=mailto:d@example.com").unwrap();
        assert!(rest.is_empty());
        assert_eq!(
            tags,
            vec![("v", "DMARC1"), ("p", "none"), ("rua", "mailto:d@example.com"),]
        );
    }

    #[test]
    fn trailing_semicolon() {
        crate::utils::tests::logging::init();
        let (rest, tags) = tag_list("v=STSv1; id=abc123;").unwrap();
        assert!(rest.is_empty());
        assert_eq!(tags, vec![("v", "STSv1"), ("id", "abc123")]);
    }

    #[test]
    fn single_tag() {
        crate::utils::tests::logging::init();
        let (rest, tags) = tag_list("v=DMARC1").unwrap();
        assert!(rest.is_empty());
        assert_eq!(tags, vec![("v", "DMARC1")]);
    }

    #[test]
    fn empty_value() {
        crate::utils::tests::logging::init();
        let (rest, tags) = tag_list("v=BIMI1; l=; a=").unwrap();
        assert!(rest.is_empty());
        assert_eq!(tags, vec![("v", "BIMI1"), ("l", ""), ("a", "")]);
    }
}
