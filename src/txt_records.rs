use nom::IResult;

#[derive(Debug, PartialEq)]
pub struct Spf<'a> {
    pub version: u32,
    pub words: Vec<Word<'a>>,
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
    A,
    IPv4(&'a str),
    IPv6(&'a str),
    MX,
    PTR,
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

impl<'a> Spf<'a> {
    pub fn from_str(txt: &'a str) -> Result<Self> {
        match parser::spf(txt.as_bytes()) {
            IResult::Error(e) => Err(Error::with_chain(e, ErrorKind::SpfParsingFailed)),
            IResult::Incomplete(_) => Err(Error::from_kind(ErrorKind::SpfParsingFailed)),
            IResult::Done(_, spf) => Ok(spf)
        }
    }
}

/// SPF Parser -- cf. https://tools.ietf.org/html/rfc4408
mod parser {
    use super::{Mechanism, Qualifier, Modifier, Word, Spf};
    use nom::*;
    use std::str;
    use std::str::FromStr;

    named!(pub spf <Spf>, do_parse!(
        version: spf_version >>
        words:   many1!(ws!(spf_word)) >>

        ( Spf { version: version, words: words} )
    ));

    named!(spf_version <u32>, do_parse!(
                    tag!("v=spf") >>
        version:    map_res!(
                        map_res!(
                          digit,
                          str::from_utf8
                        ),
                        FromStr::from_str
                    ) >>

        (version)
    ));

    named!(spf_word <Word>, alt!(
        spf_word_word | spf_word_modifier
    ));


    named!(spf_word_word <Word>, do_parse!(
        qualifier: map!(
            opt!(
                alt!(
                    char!('+') | char!('?') | char!('~') | char!('-')
                )
            ),
            Qualifier::from
        ) >>
        mechanism: spf_mechanism >>

        (Word::Word(qualifier, mechanism))
    ));

    named!(spf_mechanism <Mechanism>, do_parse!(
        mechanism:   alt!(
                        spf_mechanism_all |
                        spf_mechanism_a |
                        spf_mechanism_ip4 |
                        spf_mechanism_ip6 |
                        spf_mechanism_mx |
                        spf_mechanism_ptr |
                        spf_mechanism_exists |
                        spf_mechanism_include
                    ) >>

        (mechanism)
    ));

    named!(spf_mechanism_all <Mechanism>, do_parse!(
        tag!("all") >> (Mechanism::All)
    ));

    named!(spf_mechanism_a <Mechanism>, do_parse!(
        tag!("a") >> (Mechanism::A)
    ));

    fn is_ipv4_addr_range_char(x: u8) -> bool {
        is_digit(x) || (x as char) == '.' || (x as char) == '/'
    }

    named!(spf_mechanism_ip4 <Mechanism>, do_parse!(
                tag!("ip4:") >>
        ip4:    map_res!(
                    take_while!(is_ipv4_addr_range_char),
                    str::from_utf8
                ) >>

        (Mechanism::IPv4(ip4))
    ));

    fn is_ipv6_addr_range_char(x: u8) -> bool {
        is_hex_digit(x) || (x as char) == ':' || (x as char) == '/'
    }

    named!(spf_mechanism_ip6 <Mechanism>, do_parse!(
                tag!("ip6:") >>
        ip6:    map_res!(
                    take_while!(is_ipv6_addr_range_char),
                    str::from_utf8
                ) >>

        (Mechanism::IPv6(ip6))
    ));

    named!(spf_mechanism_mx <Mechanism>, do_parse!(
        tag!("mx") >> (Mechanism::MX)
    ));

    named!(spf_mechanism_ptr <Mechanism>, do_parse!(
        tag!("ptr") >> (Mechanism::PTR)
    ));

    fn is_domain_spec_char(x: u8) -> bool {
        is_alphanumeric(x) || ".-+,/_=%{}".contains(x as char)
    }

    named!(spf_mechanism_exists <Mechanism>, do_parse!(
                tag!("exists:") >>
        exists: map_res!(
                    take_while!(is_domain_spec_char),
                    str::from_utf8
                ) >>
        (Mechanism::Exists(exists))
    ));

    named!(spf_mechanism_include <Mechanism>, do_parse!(
                tag!("include:") >>
        incl:   map_res!(
                    take_while!(is_domain_spec_char),
                    str::from_utf8
                ) >>

        (Mechanism::Include(incl))
    ));

    named!(spf_word_modifier <Word>, do_parse!(
        modifier:   alt!(
                        spf_modifier_redirect | spf_modifier_exp
                    ) >>

        (Word::Modifier(modifier))
    ));

    named!(spf_modifier_redirect <Modifier>, do_parse!(
                     tag!("redirect=") >>
        domain_spec: map_res!(
                        take_while!(is_domain_spec_char),
                        str::from_utf8
                     ) >>

        (Modifier::Redirect(domain_spec))
    ));

    named!(spf_modifier_exp <Modifier>, do_parse!(
                     tag!("exp=") >>
        domain_spec: map_res!(
                        take_while!(is_domain_spec_char),
                        str::from_utf8
                     ) >>

        (Modifier::Exp(domain_spec))
    ));
}

error_chain! {
    errors {
        SpfParsingFailed {
            description("Failed to parse SPF record")
            display("Failed to parse SPF record")
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use super::parser::spf;
    use nom::ErrorKind::Digit;

    #[test]
    fn xmas() {
        let record = b"v=spf1 ip4:192.168.0.0/24 +ip6:fc00::/7 ?a ~mx -ptr exists:%{ir}.%{l1r+-}._spf.%{d} ?include:_spf.example.com redirect=_spf.example.com exp=explain._spf.%{d} -all";

        let spf_parsed = Spf {
            version: 1,
            words: vec![
                Word::Word(Qualifier::Pass, Mechanism::IPv4("192.168.0.0/24")),
                Word::Word(Qualifier::Pass, Mechanism::IPv6("fc00::/7")),
                Word::Word(Qualifier::Neutral, Mechanism::A),
                Word::Word(Qualifier::Softfail, Mechanism::MX),
                Word::Word(Qualifier::Fail, Mechanism::PTR),
                Word::Word(Qualifier::Pass, Mechanism::Exists("%{ir}.%{l1r+-}._spf.%{d}")),
                Word::Word(Qualifier::Neutral, Mechanism::Include("_spf.example.com")),
                Word::Modifier(Modifier::Redirect("_spf.example.com")),
                Word::Modifier(Modifier::Exp("explain._spf.%{d}")),
                Word::Word(Qualifier::Fail, Mechanism::All),
            ]
        };

        assert_eq!(IResult::Done(&[][..], spf_parsed), spf(record));
    }

    #[test]
    fn example_com() {
        let record = b"v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.123 a -all";

        let spf_parsed = Spf {
            version: 1,
            words: vec![
                Word::Word(Qualifier::Pass, Mechanism::IPv4("192.0.2.0/24")),
                Word::Word(Qualifier::Pass, Mechanism::IPv4("198.51.100.123")),
                Word::Word(Qualifier::Pass, Mechanism::A),
                Word::Word(Qualifier::Fail, Mechanism::All),
            ]
        };

        assert_eq!(IResult::Done(&[][..], spf_parsed), spf(record));
    }

    #[test]
    fn fail() {
        let record = b"v=spfx ip4:192.0.2.0/24 ip4:198.51.100.123 a -all";

        assert_eq!(IResult::Error(Digit), spf(record));
    }
}
