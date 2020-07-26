use nom::Err;

use crate::{Error, Result};

#[derive(Debug, PartialEq)]
pub struct Spf<'a> {
    version: u32,
    words: Vec<Word<'a>>,
}

#[allow(clippy::should_implement_trait)]
impl<'a> Spf<'a> {
    pub fn from_str(txt: &'a str) -> Result<Spf<'a>> {
        match parser::spf(txt) {
            Ok((_, spf)) => Ok(spf),
            Err(Err::Incomplete(_)) => Err(Error::ParserError {
                what: txt.to_string(),
                to: "SPF TXT record",
                why: "input is incomplete".to_string(),
            }),
            Err(Err::Error((what, why))) | Err(Err::Failure((what, why))) => Err(Error::ParserError {
                what: what.to_string(),
                to: "SPF TXT record",
                why: why.description().to_string(),
            }),
        }
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn words(&self) -> &Vec<Word<'a>> {
        &self.words
    }
}

#[derive(Debug, PartialEq)]
pub enum Word<'a> {
    Word(Qualifier, Mechanism<'a>),
    Modifier(Modifier<'a>),
}

#[derive(Debug, PartialEq)]
pub enum Qualifier {
    // +
    Pass,
    // ?
    Neutral,
    // ~
    Softfail,
    // -
    Fail,
}

#[derive(Debug, PartialEq)]
pub enum Mechanism<'a> {
    All,
    A {
        domain_spec: Option<&'a str>,
        cidr_len: Option<&'a str>,
    },
    IPv4(&'a str),
    IPv6(&'a str),
    MX {
        domain_spec: Option<&'a str>,
        cidr_len: Option<&'a str>,
    },
    PTR(Option<&'a str>),
    Exists(&'a str),
    Include(&'a str),
}

#[derive(Debug, PartialEq)]
pub enum Modifier<'a> {
    Redirect(&'a str),
    Exp(&'a str),
}

impl From<Option<char>> for Qualifier {
    fn from(c_opt: Option<char>) -> Self {
        match c_opt {
            Some('?') => Qualifier::Neutral,
            Some('~') => Qualifier::Softfail,
            Some('-') => Qualifier::Fail,
            Some(_) | None => Qualifier::Pass,
        }
    }
}

/// SPF Parser -- cf. https://tools.ietf.org/html/rfc4408
pub(crate) mod parser {
    use std::str;

    use nom::branch::alt;
    use nom::bytes::complete::{tag, take_while};
    use nom::character::complete::{char, digit1, space1};
    use nom::combinator::{map, map_res, opt};
    use nom::multi::many1;
    use nom::*;

    use super::{Mechanism, Modifier, Qualifier, Spf, Word};

    pub fn spf(input: &str) -> IResult<&str, Spf> {
        let (input, version) = spf_version(input)?;
        let (input, words) = many1(spf_word)(input)?;

        Ok((input, Spf { version, words }))
    }

    fn spf_version(input: &str) -> IResult<&str, u32> {
        let (input, _) = tag("v=spf")(input)?;
        let (input, version) = map_res(digit1, |s: &str| s.parse::<u32>())(input)?;

        Ok((input, version))
    }

    fn spf_word(input: &str) -> IResult<&str, Word> {
        let (input, _) = space1(input)?;
        alt((spf_word_word, spf_word_modifier))(input)
    }

    fn spf_word_word(input: &str) -> IResult<&str, Word> {
        let (input, qualifier) = map(opt(alt((char('+'), char('?'), char('~'), char('-')))), Qualifier::from)(input)?;
        let (input, mechanism) = spf_mechanism(input)?;

        Ok((input, Word::Word(qualifier, mechanism)))
    }

    fn spf_mechanism(input: &str) -> IResult<&str, Mechanism> {
        let (input, mechanism) = alt((
            spf_mechanism_all,
            spf_mechanism_a,
            spf_mechanism_ip4,
            spf_mechanism_ip6,
            spf_mechanism_mx,
            spf_mechanism_ptr,
            spf_mechanism_exists,
            spf_mechanism_include,
        ))(input)?;

        Ok((input, mechanism))
    }

    fn spf_mechanism_all(input: &str) -> IResult<&str, Mechanism> {
        let (input, _) = tag("all")(input)?;
        Ok((input, Mechanism::All))
    }

    fn spf_mechanism_a(input: &str) -> IResult<&str, Mechanism> {
        let (input, _) = tag("a")(input)?;
        let (input, domain_spec) = opt(domain_spec)(input)?;
        let (input, cidr_len) = opt(cidr_len)(input)?;
        Ok((input, Mechanism::A { domain_spec, cidr_len }))
    }

    fn domain_spec(input: &str) -> IResult<&str, &str> {
        let (input, _) = tag(":")(input)?;
        let (input, domain_spec) =
            map_res(take_while(is_domain_spec_char), |s: &str| str::from_utf8(s.as_bytes()))(input)?;

        Ok((input, domain_spec))
    }

    fn cidr_len(input: &str) -> IResult<&str, &str> {
        let (input, _) = tag("/")(input)?;
        let (input, cidr_len) = map_res(digit1, |s: &str| str::from_utf8(s.as_bytes()))(input)?;

        Ok((input, cidr_len))
    }

    fn is_domain_spec_char(c: char) -> bool {
        c.is_alphanumeric() || ".-_".contains(c)
    }

    fn spf_mechanism_ip4(input: &str) -> IResult<&str, Mechanism> {
        let (input, _) = tag("ip4:")(input)?;
        let (input, ipv4) = map_res(take_while(is_ipv4_addr_range_char), |s: &str| {
            str::from_utf8(s.as_bytes())
        })(input)?;

        Ok((input, Mechanism::IPv4(ipv4)))
    }

    fn is_ipv4_addr_range_char(c: char) -> bool {
        c.is_digit(10) || c == '.' || c == '/'
    }

    fn spf_mechanism_ip6(input: &str) -> IResult<&str, Mechanism> {
        let (input, _) = tag("ip6:")(input)?;
        let (input, ipv6) = map_res(take_while(is_ipv6_addr_range_char), |s: &str| {
            str::from_utf8(s.as_bytes())
        })(input)?;

        Ok((input, Mechanism::IPv6(ipv6)))
    }

    fn is_ipv6_addr_range_char(c: char) -> bool {
        c.is_hex_digit() || c == ':' || c == '/'
    }

    fn spf_mechanism_mx(input: &str) -> IResult<&str, Mechanism> {
        let (input, _) = tag("mx")(input)?;
        let (input, domain_spec) = opt(domain_spec)(input)?;
        let (input, cidr_len) = opt(cidr_len)(input)?;
        Ok((input, Mechanism::MX { domain_spec, cidr_len }))
    }

    fn spf_mechanism_ptr(input: &str) -> IResult<&str, Mechanism> {
        let (input, _) = tag("ptr")(input)?;
        let (input, domain_spec) = opt(domain_spec)(input)?;
        Ok((input, Mechanism::PTR(domain_spec)))
    }

    fn spf_mechanism_exists(input: &str) -> IResult<&str, Mechanism> {
        let (input, _) = tag("exists:")(input)?;
        let (input, domain_spec) = map_res(take_while(is_domain_spec_macro_char), |s: &str| {
            str::from_utf8(s.as_bytes())
        })(input)?;

        Ok((input, Mechanism::Exists(domain_spec)))
    }

    fn is_domain_spec_macro_char(c: char) -> bool {
        c.is_alphanumeric() || ".-+,/_=%{}".contains(c)
    }

    fn spf_mechanism_include(input: &str) -> IResult<&str, Mechanism> {
        let (input, _) = tag("include:")(input)?;
        let (input, domain_spec) =
            map_res(take_while(is_domain_spec_char), |s: &str| str::from_utf8(s.as_bytes()))(input)?;

        Ok((input, Mechanism::Include(domain_spec)))
    }

    fn spf_word_modifier(input: &str) -> IResult<&str, Word> {
        let (input, modifier) = alt((spf_modifier_redirect, spf_modifier_exp))(input)?;

        Ok((input, Word::Modifier(modifier)))
    }

    fn spf_modifier_redirect(input: &str) -> IResult<&str, Modifier> {
        let (input, _) = tag("redirect=")(input)?;
        let (input, domain_spec) =
            map_res(take_while(is_domain_spec_char), |s: &str| str::from_utf8(s.as_bytes()))(input)?;

        Ok((input, Modifier::Redirect(domain_spec)))
    }

    fn spf_modifier_exp(input: &str) -> IResult<&str, Modifier> {
        let (input, _) = tag("exp=")(input)?;
        let (input, domain_spec) = map_res(take_while(is_domain_spec_macro_char), |s: &str| {
            str::from_utf8(s.as_bytes())
        })(input)?;

        Ok((input, Modifier::Exp(domain_spec)))
    }
}

#[cfg(test)]
mod test {
    use super::parser::spf;
    use super::*;

    #[test]
    fn xmas() {
        let record = "v=spf1 ip4:192.168.0.0/24 +ip6:fc00::/7 ?a a/24 a:offsite.example.com/24 ~mx mx/24 mx:mx.example.com/24 -ptr +ptr:mx.example.com exists:%{ir}.%{l1r+-}._spf.%{d} ?include:_spf.example.com redirect=_spf.example.com exp=explain._spf.%{d} -all";

        let expected = Spf {
            version: 1,
            words: vec![
                Word::Word(Qualifier::Pass, Mechanism::IPv4("192.168.0.0/24")),
                Word::Word(Qualifier::Pass, Mechanism::IPv6("fc00::/7")),
                Word::Word(
                    Qualifier::Neutral,
                    Mechanism::A {
                        domain_spec: None,
                        cidr_len: None,
                    },
                ),
                Word::Word(
                    Qualifier::Pass,
                    Mechanism::A {
                        domain_spec: None,
                        cidr_len: Some("24"),
                    },
                ),
                Word::Word(
                    Qualifier::Pass,
                    Mechanism::A {
                        domain_spec: Some("offsite.example.com"),
                        cidr_len: Some("24"),
                    },
                ),
                Word::Word(
                    Qualifier::Softfail,
                    Mechanism::MX {
                        domain_spec: None,
                        cidr_len: None,
                    },
                ),
                Word::Word(
                    Qualifier::Pass,
                    Mechanism::MX {
                        domain_spec: None,
                        cidr_len: Some("24"),
                    },
                ),
                Word::Word(
                    Qualifier::Pass,
                    Mechanism::MX {
                        domain_spec: Some("mx.example.com"),
                        cidr_len: Some("24"),
                    },
                ),
                Word::Word(Qualifier::Fail, Mechanism::PTR(None)),
                Word::Word(Qualifier::Pass, Mechanism::PTR(Some("mx.example.com"))),
                Word::Word(Qualifier::Pass, Mechanism::Exists("%{ir}.%{l1r+-}._spf.%{d}")),
                Word::Word(Qualifier::Neutral, Mechanism::Include("_spf.example.com")),
                Word::Modifier(Modifier::Redirect("_spf.example.com")),
                Word::Modifier(Modifier::Exp("explain._spf.%{d}")),
                Word::Word(Qualifier::Fail, Mechanism::All),
            ],
        };

        let (_, spf) = spf(record).expect("failed to parse SPF record");

        assert_eq!(spf, expected);
    }

    #[test]
    fn example_com() {
        let record = "v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.123 a -all";

        let expected = Spf {
            version: 1,
            words: vec![
                Word::Word(Qualifier::Pass, Mechanism::IPv4("192.0.2.0/24")),
                Word::Word(Qualifier::Pass, Mechanism::IPv4("198.51.100.123")),
                Word::Word(
                    Qualifier::Pass,
                    Mechanism::A {
                        domain_spec: None,
                        cidr_len: None,
                    },
                ),
                Word::Word(Qualifier::Fail, Mechanism::All),
            ],
        };

        let (_, spf) = spf(record).expect("failed to parse SPF record");

        assert_eq!(spf, expected);
    }

    #[test]
    fn fail() {
        let record = "v=spfx ip4:192.0.2.0/24 ip4:198.51.100.123 a -all";

        let res = spf(record);

        assert!(res.is_err());
    }
}
