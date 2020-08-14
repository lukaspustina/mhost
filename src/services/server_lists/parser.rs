use std::cell::Cell;

use nom::branch::alt;
use nom::bytes::complete::{tag, take_while1};
use nom::combinator::map_res;
use nom::multi::separated_list;
use nom::IResult;

use crate::services::server_lists::{OpenNic, PublicDns, IPV};

use super::*;

pub(crate) fn parse_server_list_spec<'a>(input: &'a str) -> IResult<&'a str, ServerListSpec> {
    let (input, spec) = alt((public_dns, opennic))(input)?;

    Ok((input, spec))
}

fn public_dns<'a>(input: &'a str) -> IResult<&'a str, ServerListSpec> {
    let (input, _) = tag("public-dns")(input)?;
    let (input, spec) = public_dns_spec(input)?;
    Ok((input, ServerListSpec::PublicDns { spec }))
}

fn public_dns_spec<'a>(input: &'a str) -> IResult<&'a str, PublicDns> {
    if input.is_empty() {
        Ok((input, Default::default()))
    } else {
        let (input, _) = tag(":")(input)?;
        let (input, country) = take_while1(|c: char| c.is_alphanumeric())(input)?;
        Ok((
            input,
            PublicDns {
                country: Some(country.to_string()),
            },
        ))
    }
}

fn opennic<'a>(input: &'a str) -> IResult<&'a str, ServerListSpec> {
    let (input, _) = tag("opennic")(input)?;
    let (input, spec) = opennic_spec(input)?;
    Ok((input, ServerListSpec::OpenNic { spec }))
}

fn opennic_spec<'a>(input: &'a str) -> IResult<&'a str, OpenNic> {
    if input.is_empty() {
        Ok((input, Default::default()))
    } else {
        let (input, spec) = opennic_spec_params(input)?;
        Ok((input, spec))
    }
}

fn opennic_spec_params<'a>(input: &'a str) -> IResult<&'a str, OpenNic> {
    let (input, _) = tag(":")(input)?;
    let spec = Cell::new(OpenNic::default());
    let (input, _) = separated_list(
        tag(","),
        alt((
            |x| opennic_spec_params_anon(&spec, x),
            |x| opennic_spec_params_number(&spec, x),
            |x| opennic_spec_params_reliability(&spec, x),
            |x| opennic_spec_params_ipv(&spec, x),
        )),
    )(input)?;

    Ok((input, spec.into_inner()))
}

fn opennic_spec_params_anon<'a>(cell: &Cell<OpenNic>, input: &'a str) -> IResult<&'a str, ()> {
    let (input, _) = tag("anon")(input)?;
    let mut spec = cell.take();
    spec.anon = true;
    cell.set(spec);

    Ok((input, ()))
}

fn opennic_spec_params_number<'a>(cell: &Cell<OpenNic>, input: &'a str) -> IResult<&'a str, ()> {
    let (input, _) = tag("number=")(input)?;
    let (input, number) = map_res(take_while1(|c: char| c.is_digit(10) || c == '.'), usize::from_str)(input)?;
    let mut spec = cell.take();
    spec.number = number;
    cell.set(spec);

    Ok((input, ()))
}

fn opennic_spec_params_reliability<'a>(cell: &Cell<OpenNic>, input: &'a str) -> IResult<&'a str, ()> {
    let (input, _) = tag("reliability=")(input)?;
    let (input, reliability) = map_res(take_while1(|c: char| c.is_digit(10) || c == '.'), usize::from_str)(input)?;
    let mut spec = cell.take();
    spec.reliability = reliability;
    cell.set(spec);

    Ok((input, ()))
}

fn opennic_spec_params_ipv<'a>(cell: &Cell<OpenNic>, input: &'a str) -> IResult<&'a str, ()> {
    let (input, _) = tag("ipv=")(input)?;
    let (input, ipv) = map_res(take_while1(|c: char| c.is_digit(10) || c == '.'), IPV::from_str)(input)?;
    let mut spec = cell.take();
    spec.ipv = ipv;
    cell.set(spec);

    Ok((input, ()))
}

#[cfg(test)]
mod tests {
    use spectral::prelude::*;

    use crate::services::server_lists::PublicDns;

    use super::*;

    #[test]
    fn public_dns_default() {
        let str = "public-dns";
        let expected = ServerListSpec::PublicDns {
            spec: Default::default(),
        };

        let (_, config) = parse_server_list_spec(&str).expect("failed to parse server list spec");

        assert_that(&config).is_equal_to(expected);
    }

    #[test]
    fn public_country() {
        let str = "public-dns:de";
        let expected = ServerListSpec::PublicDns {
            spec: PublicDns {
                country: Some("de".to_string()),
            },
        };

        let (_, config) = parse_server_list_spec(&str).expect("failed to parse server list spec");

        assert_that(&config).is_equal_to(expected);
    }

    #[test]
    fn public_separator_missing_country() {
        let str = "public-dns:";

        let res = parse_server_list_spec(&str);

        assert_that(&res).is_err();
    }

    #[test]
    fn opennic_default() {
        let str = "opennic";
        let expected = ServerListSpec::OpenNic {
            spec: Default::default(),
        };

        let (_, config) = parse_server_list_spec(&str).expect("failed to parse server list spec");

        assert_that(&config).is_equal_to(expected);
        assert_that(&config.opennic())
            .is_some()
            .map(|x| &x.anon)
            .is_equal_to(false);
    }

    #[test]
    fn opennic_anon() {
        let str = "opennic:anon";
        let expected = ServerListSpec::OpenNic {
            spec: OpenNic {
                anon: true,
                ..Default::default()
            },
        };

        let (_, config) = parse_server_list_spec(&str).expect("failed to parse server list spec");

        assert_that(&config).is_equal_to(expected);
        assert_that(&config.opennic())
            .is_some()
            .map(|x| &x.anon)
            .is_equal_to(true);
    }

    #[test]
    fn opennic_number() {
        let str = "opennic:number=100";
        let expected = ServerListSpec::OpenNic {
            spec: OpenNic {
                number: 100,
                ..Default::default()
            },
        };

        let (_, config) = parse_server_list_spec(&str).expect("failed to parse server list spec");

        assert_that(&config).is_equal_to(expected);
    }

    #[test]
    fn opennic_reliability() {
        let str = "opennic:reliability=40";
        let expected = ServerListSpec::OpenNic {
            spec: OpenNic {
                reliability: 40,
                ..Default::default()
            },
        };

        let (_, config) = parse_server_list_spec(&str).expect("failed to parse server list spec");

        assert_that(&config).is_equal_to(expected);
    }

    #[test]
    fn opennic_ipv4() {
        let str = "opennic:ipv=4";
        let expected = ServerListSpec::OpenNic {
            spec: OpenNic {
                ipv: IPV::V4,
                ..Default::default()
            },
        };

        let (_, config) = parse_server_list_spec(&str).expect("failed to parse server list spec");

        assert_that(&config).is_equal_to(expected);
    }

    #[test]
    fn opennic_all() {
        let str = "opennic:anon,number=100,reliability=50,ipv=6";
        let expected = ServerListSpec::OpenNic {
            spec: OpenNic {
                anon: true,
                number: 100,
                reliability: 50,
                ipv: IPV::V6,
            },
        };

        let (_, config) = parse_server_list_spec(&str).expect("failed to parse server list spec");

        assert_that(&config).is_equal_to(expected);
    }
}
