// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::net::IpAddr;

use nom::Err;

use crate::nameserver::NameServerConfig;
use crate::resolver::lookup::Uniquify;
use crate::resolver::{MultiQuery, ResolverGroup};
use crate::RecordType;
use crate::{Error, Result};

#[allow(clippy::should_implement_trait)]
impl NameServerConfig {
    pub async fn from_str_with_resolution(resolvers: &ResolverGroup, str: &str) -> Result<NameServerConfig> {
        match parser::parsed_name_server_config(str) {
            Ok((_, result)) => {
                let ip = target_to_ip(resolvers, &result.target).await?;
                result.try_into(ip)
            }
            Err(Err::Incomplete(_)) => Err(Error::ParserError {
                what: str.to_string(),
                to: "NameServerConfig",
                why: "input is incomplete".to_string(),
            }),
            Err(Err::Error((what, why))) | Err(Err::Failure((what, why))) => Err(Error::ParserError {
                what: what.to_string(),
                to: "NameServerConfig",
                why: why.description().to_string(),
            }),
        }
    }

    pub fn from_str(str: &str) -> Result<NameServerConfig> {
        match parser::parsed_name_server_config(str) {
            Ok((_, result)) => match &result.target {
                parser::Target::Ipv4(ip) => {
                    let ip = *ip;
                    result.try_into(IpAddr::V4(ip))
                }
                parser::Target::Ipv6(ip) => {
                    let ip = *ip;
                    result.try_into(IpAddr::V6(ip))
                }
                parser::Target::Name(name) => Err(Error::ParserError {
                    what: name.to_string(),
                    to: "NameServerConfig",
                    why: "IP address required, name given".to_string(),
                }),
            },
            Err(Err::Incomplete(_)) => Err(Error::ParserError {
                what: str.to_string(),
                to: "NameServerConfig",
                why: "input is incomplete".to_string(),
            }),
            Err(Err::Error((what, why))) | Err(Err::Failure((what, why))) => Err(Error::ParserError {
                what: what.to_string(),
                to: "NameServerConfig",
                why: why.description().to_string(),
            }),
        }
    }
}

impl<'a> parser::NameServerConfig<'a> {
    fn try_into(self, target_ip: IpAddr) -> Result<NameServerConfig> {
        use parser::Protocol;
        match &self.protocol {
            Protocol::Udp => try_udp_from(target_ip, self),
            Protocol::Tcp => try_tcp_from(target_ip, self),
            Protocol::Tls => try_tls_from(target_ip, self),
            Protocol::Https => try_https_from(target_ip, self),
        }
    }
}

fn try_udp_from(ip: IpAddr, config: parser::NameServerConfig) -> Result<NameServerConfig> {
    use parser::NameServerConfig;
    match config {
        NameServerConfig {
            protocol: _,
            target: _,
            port,
            tls_auth_name: Option::None,
            name,
        } => Ok(crate::nameserver::NameServerConfig::udp_with_name(
            (ip, port),
            name.map(ToString::to_string),
        )),
        NameServerConfig {
            protocol: _,
            target: _,
            port: _,
            tls_auth_name: Some(tls_auth_name),
            name: _,
        } => Err(Error::ParserError {
            what: tls_auth_name.to_string(),
            to: "NameServerConfig",
            why: "illegal parameter 'tls_auth_name' for udp".to_string(),
        }),
    }
}

fn try_tcp_from(ip: IpAddr, config: parser::NameServerConfig) -> Result<NameServerConfig> {
    use parser::NameServerConfig;
    match config {
        NameServerConfig {
            protocol: _,
            target: _,
            port,
            tls_auth_name: Option::None,
            name,
        } => Ok(crate::nameserver::NameServerConfig::tcp_with_name(
            (ip, port),
            name.map(ToString::to_string),
        )),
        NameServerConfig {
            protocol: _,
            target: _,
            port: _,
            tls_auth_name: Some(tls_auth_name),
            name: _,
        } => Err(Error::ParserError {
            what: tls_auth_name.to_string(),
            to: "NameServerConfig",
            why: "illegal parameter 'tls_auth_name' for tcp".to_string(),
        }),
    }
}

fn try_tls_from(ip: IpAddr, config: parser::NameServerConfig) -> Result<NameServerConfig> {
    use parser::{NameServerConfig, Target};
    match config {
        NameServerConfig {
            protocol: _,
            target: Target::Name(target_name),
            port,
            tls_auth_name: Option::None,
            name,
        } => Ok(crate::nameserver::NameServerConfig::tls_with_name(
            (ip, port),
            target_name,
            name.map(ToString::to_string),
        )),
        NameServerConfig {
            protocol: _,
            target: _,
            port,
            tls_auth_name: Some(tls_auth_name),
            name,
        } => Ok(crate::nameserver::NameServerConfig::tls_with_name(
            (ip, port),
            tls_auth_name,
            name.map(ToString::to_string),
        )),
        NameServerConfig {
            protocol: _,
            target: _,
            port: _,
            tls_auth_name: Option::None,
            name: _,
        } => Err(Error::ParserError {
            what: "tls_auth_name".to_string(),
            to: "NameServerConfig",
            why: "missing parameter 'tls_auth_name' for tls".to_string(),
        }),
    }
}

fn try_https_from(ip: IpAddr, config: parser::NameServerConfig) -> Result<NameServerConfig> {
    use parser::{NameServerConfig, Target};
    match config {
        NameServerConfig {
            protocol: _,
            target: Target::Name(target_name),
            port,
            tls_auth_name: Option::None,
            name,
        } => Ok(crate::nameserver::NameServerConfig::https_with_name(
            (ip, port),
            target_name,
            name.map(ToString::to_string),
        )),
        NameServerConfig {
            protocol: _,
            target: _,
            port,
            tls_auth_name: Some(tls_auth_name),
            name,
        } => Ok(crate::nameserver::NameServerConfig::https_with_name(
            (ip, port),
            tls_auth_name,
            name.map(ToString::to_string),
        )),
        NameServerConfig {
            protocol: _,
            target: _,
            port: _,
            tls_auth_name: Option::None,
            name: _,
        } => Err(Error::ParserError {
            what: "tls_auth_name".to_string(),
            to: "NameServerConfig",
            why: "missing parameter 'tls_auth_name' for https".to_string(),
        }),
    }
}

async fn target_to_ip(resolvers: &ResolverGroup, target: &parser::Target<'_>) -> Result<IpAddr> {
    use parser::Target;
    match *target {
        Target::Ipv4(ip) => Ok(IpAddr::V4(ip)),
        Target::Ipv6(ip) => Ok(IpAddr::V6(ip)),
        Target::Name(name) => resolve_name(resolvers, name).await,
    }
}

async fn resolve_name(resolvers: &ResolverGroup, name: &str) -> Result<IpAddr> {
    let query =
        MultiQuery::multi_record(name, vec![RecordType::A, RecordType::AAAA]).map_err(|_| Error::ParserError {
            what: name.to_string(),
            to: "IpAddr",
            why: "failed to resolve name".to_string(),
        })?;
    let lookups = resolvers.lookup(query).await?;
    let ipv4 = lookups.a().unique().to_owned().into_iter().next().map(IpAddr::V4);
    let ipv6 = lookups.aaaa().unique().to_owned().into_iter().next().map(IpAddr::V6);
    vec![ipv4, ipv6]
        .into_iter()
        .flatten()
        .next()
        .ok_or_else(|| Error::ParserError {
            what: name.to_string(),
            to: "IpAddr",
            why: "no A or AAAA record found".to_string(),
        })
}

#[cfg(test)]
mod test {
    use crate::nameserver::NameServerConfig;
    use crate::resolver::ResolverGroup;
    use spectral::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[tokio::test]
    async fn ipv4_8_8_8_8() {
        crate::utils::tests::logging::init();
        let resolvers = ResolverGroup::from_system_config(Default::default())
            .await
            .expect("failed to create system resolver");
        let str = "8.8.8.8";
        let expected = NameServerConfig::udp((Ipv4Addr::new(8, 8, 8, 8), 53));

        let config = NameServerConfig::from_str_with_resolution(&resolvers, str).await;

        assert_that(&config).is_ok().is_equal_to(&expected);
    }

    #[tokio::test]
    async fn tcp_8_8_8_8() {
        crate::utils::tests::logging::init();
        let resolvers = ResolverGroup::from_system_config(Default::default())
            .await
            .expect("failed to create system resolver");
        let str = "tcp:8.8.8.8";
        let expected = NameServerConfig::tcp((Ipv4Addr::new(8, 8, 8, 8), 53));

        let config = NameServerConfig::from_str_with_resolution(&resolvers, str).await;

        assert_that(&config).is_ok().is_equal_to(&expected);
    }

    #[tokio::test]
    async fn ipv4_8_8_8_8_port() {
        crate::utils::tests::logging::init();
        let resolvers = ResolverGroup::from_system_config(Default::default())
            .await
            .expect("failed to create system resolver");
        let str = "8.8.8.8:35";
        let expected = NameServerConfig::udp((Ipv4Addr::new(8, 8, 8, 8), 35));

        let config = NameServerConfig::from_str_with_resolution(&resolvers, str).await;

        assert_that(&config).is_ok().is_equal_to(&expected);
    }

    #[tokio::test]
    async fn tcp_8_8_8_8_port() {
        crate::utils::tests::logging::init();
        let resolvers = ResolverGroup::from_system_config(Default::default())
            .await
            .expect("failed to create system resolver");
        let str = "tcp:8.8.8.8:35";
        let expected = NameServerConfig::tcp((Ipv4Addr::new(8, 8, 8, 8), 35));

        let config = NameServerConfig::from_str_with_resolution(&resolvers, str).await;

        assert_that(&config).is_ok().is_equal_to(&expected);
    }

    #[tokio::test]
    async fn tcp_8_8_8_8_port_name() {
        crate::utils::tests::logging::init();
        let resolvers = ResolverGroup::from_system_config(Default::default())
            .await
            .expect("failed to create system resolver");
        let str = "tcp:8.8.8.8:35,name=Google DNS";
        let expected = NameServerConfig::tcp_with_name((Ipv4Addr::new(8, 8, 8, 8), 35), "Google DNS".to_string());

        let config = NameServerConfig::from_str_with_resolution(&resolvers, str).await;

        assert_that(&config).is_ok().is_equal_to(&expected);
    }

    #[tokio::test]
    async fn tcp_8_8_8_8_port_tls_auth_name() {
        crate::utils::tests::logging::init();
        let resolvers = ResolverGroup::from_system_config(Default::default())
            .await
            .expect("failed to create system resolver");
        let str = "tcp:8.8.8.8:35,tls_auth_name=dns.google";

        let config = NameServerConfig::from_str_with_resolution(&resolvers, str).await;

        assert_that(&config).is_err();
    }

    #[tokio::test]
    #[allow(non_snake_case)]
    async fn ipv4_2606_4700__6810_f9f9() {
        crate::utils::tests::logging::init();
        let resolvers = ResolverGroup::from_system_config(Default::default())
            .await
            .expect("failed to create system resolver");
        let str = "2606:4700::6810:f9f9";
        let expected = NameServerConfig::udp((Ipv6Addr::from_str("2606:4700::6810:f9f9").unwrap(), 53));

        let config = NameServerConfig::from_str_with_resolution(&resolvers, str).await;

        assert_that(&config).is_ok().is_equal_to(&expected);
    }

    #[tokio::test]
    async fn dns_google() {
        crate::utils::tests::logging::init();
        let resolvers = ResolverGroup::from_system_config(Default::default())
            .await
            .expect("failed to create system resolver");
        let str = "dns.google";
        let expected1 = NameServerConfig::udp((Ipv4Addr::new(8, 8, 8, 8), 53));
        let expected2 = NameServerConfig::udp((Ipv4Addr::new(8, 8, 4, 4), 53));

        let config = NameServerConfig::from_str_with_resolution(&resolvers, str).await;

        assert_that(&config).is_ok();
        assert_that(&[expected1, expected2]).contains(config.unwrap());
    }

    #[tokio::test]
    async fn tls_cloudflare_dns_com_tls_auth_name() {
        crate::utils::tests::logging::init();
        let resolvers = ResolverGroup::from_system_config(Default::default())
            .await
            .expect("failed to create system resolver");
        let str = "tls:cloudflare-dns.com,tls_auth_name=cloudflare-dns.com";
        let expected1 = NameServerConfig::tls(
            (Ipv4Addr::new(104, 16, 248, 249), 853),
            "cloudflare-dns.com".to_string(),
        );
        let expected2 = NameServerConfig::tls(
            (Ipv4Addr::new(104, 16, 249, 249), 853),
            "cloudflare-dns.com".to_string(),
        );

        let config = NameServerConfig::from_str_with_resolution(&resolvers, str).await;

        assert_that(&config).is_ok();
        assert_that(&[expected1, expected2]).contains(config.unwrap());
    }

    #[tokio::test]
    async fn tls_104_16_249_249_tls_auth_name_name() {
        crate::utils::tests::logging::init();
        let resolvers = ResolverGroup::from_system_config(Default::default())
            .await
            .expect("failed to create system resolver");
        let str = "tls:104.16.249.249,tls_auth_name=cloudflare-dns.com,name=Cloudflare";
        let expected = NameServerConfig::tls_with_name(
            (Ipv4Addr::new(104, 16, 249, 249), 853),
            "cloudflare-dns.com".to_string(),
            "Cloudflare".to_string(),
        );

        let config = NameServerConfig::from_str_with_resolution(&resolvers, str).await;

        assert_that(&config).is_ok().is_equal_to(expected);
    }

    #[tokio::test]
    #[allow(non_snake_case)]
    async fn https_slash_slash_2606_4700__6810_f8f9_tls_auth_name_name() {
        crate::utils::tests::logging::init();
        let resolvers = ResolverGroup::from_system_config(Default::default())
            .await
            .expect("failed to create system resolver");
        let str = "https://2606:4700::6810:f8f9,tls_auth_name=cloudflare-dns.com,name=Cloudflare";
        let expected = NameServerConfig::https_with_name(
            (Ipv6Addr::from_str("2606:4700::6810:f8f9").unwrap(), 443),
            "cloudflare-dns.com".to_string(),
            "Cloudflare".to_string(),
        );

        let config = NameServerConfig::from_str_with_resolution(&resolvers, str).await;

        assert_that(&config).is_ok().is_equal_to(expected);
    }
}

#[allow(clippy::module_inception)]
pub(crate) mod parser {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    use nom::branch::alt;
    use nom::bytes::complete::{tag, take_while};
    use nom::character::complete::digit1;
    use nom::combinator::{map_res, opt};
    use nom::{AsChar, IResult};

    #[derive(Debug, PartialEq, Eq)]
    pub(crate) struct NameServerConfig<'a> {
        pub protocol: Protocol,
        pub target: Target<'a>,
        pub port: u16,
        pub tls_auth_name: Option<&'a str>,
        pub name: Option<&'a str>,
    }

    impl<'a> NameServerConfig<'a> {
        #[allow(dead_code)]
        pub(crate) fn new(protocol: Protocol, target: Target, port: u16) -> NameServerConfig {
            NameServerConfig {
                protocol,
                target,
                port,
                tls_auth_name: None,
                name: None,
            }
        }

        pub(crate) fn new_with_tls_auth_name_and_name<S: Into<Option<&'a str>>, T: Into<Option<&'a str>>>(
            protocol: Protocol,
            target: Target<'a>,
            port: u16,
            tls_auth_name: S,
            name: T,
        ) -> NameServerConfig<'a> {
            NameServerConfig {
                protocol,
                target,
                port,
                tls_auth_name: tls_auth_name.into(),
                name: name.into(),
            }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    pub(crate) enum Protocol {
        Udp,
        Tcp,
        Https,
        Tls,
    }

    impl FromStr for Protocol {
        type Err = super::Error;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s {
                "udp" => Ok(Protocol::Udp),
                "tcp" => Ok(Protocol::Tcp),
                "https" => Ok(Protocol::Https),
                "tls" => Ok(Protocol::Tls),
                _ => Err(Self::Err::ParserError {
                    what: s.to_string(),
                    to: "Protocol",
                    why: "unsupported protocol".to_string(),
                }),
            }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    pub(crate) enum Target<'a> {
        Ipv4(Ipv4Addr),
        Ipv6(Ipv6Addr),
        Name(&'a str),
    }

    pub(crate) fn parsed_name_server_config(input: &str) -> IResult<&str, NameServerConfig> {
        let (input, protocol) = opt(protocol)(input)?;
        let (input, target) = alt((ipv4, ipv6, name))(input)?;
        let (input, port) = opt(port)(input)?;
        let (input, tls_auth_name) = opt(tls_auth_name)(input)?;
        let (input, name) = opt(ns_name)(input)?;

        let protocol = protocol.unwrap_or(Protocol::Udp);
        let port = port.unwrap_or_else(|| default_port_for(&protocol));
        let config = NameServerConfig::new_with_tls_auth_name_and_name(protocol, target, port, tls_auth_name, name);

        Ok((input, config))
    }

    fn protocol(input: &str) -> IResult<&str, Protocol> {
        let (input, protocol) = map_res(
            alt((tag("udp"), tag("tcp"), tag("https"), tag("tls"))),
            Protocol::from_str,
        )(input)?;

        let (input, _) = tag(":")(input)?;
        let (input, _) = opt(tag("//"))(input)?;

        Ok((input, protocol))
    }

    fn ipv4(input: &str) -> IResult<&str, Target> {
        let (input, ipv4) = map_res(take_while(|c: char| c.is_ascii_digit() || c == '.'), Ipv4Addr::from_str)(input)?;

        let target = Target::Ipv4(ipv4);

        Ok((input, target))
    }

    fn ipv6(input: &str) -> IResult<&str, Target> {
        let (input, _) = opt(tag("["))(input)?;
        let (input, ipv6) = map_res(
            take_while(|c: char| c.is_hex_digit() || c == ':' || c == '/'),
            Ipv6Addr::from_str,
        )(input)?;
        let (input, _) = opt(tag("]"))(input)?;

        let target = Target::Ipv6(ipv6);

        Ok((input, target))
    }

    fn name(input: &str) -> IResult<&str, Target> {
        let (input, name) = take_while(|c: char| c.is_alphanumeric() || c == '.' || c == '-')(input)?;
        let target = if name == "localhost" {
            Target::Ipv4(Ipv4Addr::new(127, 0, 0, 1))
        } else {
            Target::Name(name)
        };

        Ok((input, target))
    }

    fn port(input: &str) -> IResult<&str, u16> {
        let (input, _) = tag(":")(input)?;
        let (input, port) = map_res(digit1, str::parse)(input)?;

        Ok((input, port))
    }

    fn default_port_for(protocol: &Protocol) -> u16 {
        match *protocol {
            Protocol::Https => 443,
            Protocol::Tls => 853,
            _ => 53,
        }
    }

    fn tls_auth_name(input: &str) -> IResult<&str, &str> {
        let (input, _) = alt((tag(",tls_auth_name="), tag(",tan=")))(input)?;
        take_while(|c: char| c.is_alphanumeric() || c == '.' || c == '-')(input)
    }

    fn ns_name(input: &str) -> IResult<&str, &str> {
        let (input, _) = tag(",name=")(input)?;
        take_while(|c: char| c.is_alphanumeric() || c == '.' || c == ' ')(input)
    }

    #[cfg(test)]
    mod test {
        use std::net::{Ipv4Addr, Ipv6Addr};
        use std::str::FromStr;

        use spectral::prelude::*;

        use super::*;

        #[test]
        fn ipv4_127_0_0_1() {
            crate::utils::tests::logging::init();
            let str = "127.0.0.1";
            let expected = NameServerConfig::new(Protocol::Udp, Target::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 53);

            let (_, config) = parsed_name_server_config(str).expect("failed to parse name server config");

            assert_that(&config).is_equal_to(expected);
        }

        #[test]
        fn udp_127_0_0_1() {
            crate::utils::tests::logging::init();
            let str = "udp:127.0.0.1";
            let expected = NameServerConfig::new(Protocol::Udp, Target::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 53);

            let (_, config) = parsed_name_server_config(str).expect("failed to parse name server config");

            assert_that(&config).is_equal_to(expected);
        }

        #[test]
        fn ipv4_127_0_0_1_port() {
            crate::utils::tests::logging::init();
            let str = "127.0.0.1:35";
            let expected = NameServerConfig::new(Protocol::Udp, Target::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 35);

            let (_, config) = parsed_name_server_config(str).expect("failed to parse name server config");

            assert_that(&config).is_equal_to(expected);
        }

        #[test]
        fn ipv4_127_0_0_1_name() {
            crate::utils::tests::logging::init();
            let str = "127.0.0.1,name=localhost";
            let expected = NameServerConfig::new_with_tls_auth_name_and_name(
                Protocol::Udp,
                Target::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
                53,
                None,
                "localhost",
            );

            let (_, config) = parsed_name_server_config(str).expect("failed to parse name server config");

            assert_that(&config).is_equal_to(expected);
        }

        #[test]
        fn udp_127_0_0_1_port() {
            crate::utils::tests::logging::init();
            let str = "udp:127.0.0.1:35";
            let expected = NameServerConfig::new(Protocol::Udp, Target::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 35);

            let (_, config) = parsed_name_server_config(str).expect("failed to parse name server config");

            assert_that(&config).is_equal_to(expected);
        }

        #[test]
        fn udp_slash_slash_127_0_0_1() {
            crate::utils::tests::logging::init();
            let str = "udp://127.0.0.1";
            let expected = NameServerConfig::new(Protocol::Udp, Target::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 53);

            let (_, config) = parsed_name_server_config(str).expect("failed to parse name server config");

            assert_that(&config).is_equal_to(expected);
        }

        #[test]
        fn udp_slash_slash_127_0_0_1_port() {
            crate::utils::tests::logging::init();
            let str = "udp://127.0.0.1:35";
            let expected = NameServerConfig::new(Protocol::Udp, Target::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 35);

            let (_, config) = parsed_name_server_config(str).expect("failed to parse name server config");

            assert_that(&config).is_equal_to(expected);
        }

        #[test]
        fn tcp_127_0_0_1() {
            crate::utils::tests::logging::init();
            let str = "tcp:127.0.0.1";
            let expected = NameServerConfig::new(Protocol::Tcp, Target::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 53);

            let (_, config) = parsed_name_server_config(str).expect("failed to parse name server config");

            assert_that(&config).is_equal_to(expected);
        }

        #[test]
        fn tcp_slash_slash_127_0_0_1() {
            crate::utils::tests::logging::init();
            let str = "tcp://127.0.0.1";
            let expected = NameServerConfig::new(Protocol::Tcp, Target::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 53);

            let (_, config) = parsed_name_server_config(str).expect("failed to parse name server config");

            assert_that(&config).is_equal_to(expected);
        }

        #[test]
        #[allow(non_snake_case)]
        fn ipv6___1_128() {
            crate::utils::tests::logging::init();
            let str = "::1";
            let expected = NameServerConfig::new(Protocol::Udp, Target::Ipv6(Ipv6Addr::from_str(str).unwrap()), 53);

            let (_, config) = parsed_name_server_config(str).expect("failed to parse name server config");

            assert_that(&config).is_equal_to(expected);
        }

        #[test]
        #[allow(non_snake_case)]
        fn ipv6_with_port() {
            crate::utils::tests::logging::init();
            let str = "[2001:0db8:85a3:08d3::0370:7344]:5353";
            let expected = NameServerConfig::new(
                Protocol::Udp,
                Target::Ipv6(Ipv6Addr::from_str("2001:0db8:85a3:08d3::0370:7344").unwrap()),
                5353,
            );

            let (_, config) = parsed_name_server_config(str).expect("failed to parse name server config");

            assert_that(&config).is_equal_to(expected);
        }

        #[test]
        fn localhost() {
            crate::utils::tests::logging::init();
            let str = "localhost";
            let expected = NameServerConfig::new(Protocol::Udp, Target::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 53);

            let (_, config) = parsed_name_server_config(str).expect("failed to parse name server config");

            assert_that(&config).is_equal_to(expected);
        }

        #[test]
        fn dns_google() {
            crate::utils::tests::logging::init();
            let str = "dns.google";
            let expected = NameServerConfig::new(Protocol::Udp, Target::Name("dns.google"), 53);

            let (_, config) = parsed_name_server_config(str).expect("failed to parse name server config");

            assert_that(&config).is_equal_to(expected);
        }

        #[test]
        fn dns_google_name() {
            crate::utils::tests::logging::init();
            let str = "dns.google,name=Google";
            let expected = NameServerConfig::new_with_tls_auth_name_and_name(
                Protocol::Udp,
                Target::Name("dns.google"),
                53,
                None,
                "Google",
            );

            let (_, config) = parsed_name_server_config(str).expect("failed to parse name server config");

            assert_that(&config).is_equal_to(expected);
        }

        #[test]
        fn tls_cloudflare_dns_com_tan() {
            crate::utils::tests::logging::init();
            let str = "tls:cloudflare-dns.com,tan=cloudflare-dns.com";
            let expected = NameServerConfig::new_with_tls_auth_name_and_name(
                Protocol::Tls,
                Target::Name("cloudflare-dns.com"),
                853,
                "cloudflare-dns.com",
                None,
            );

            let (_, config) = parsed_name_server_config(str).expect("failed to parse name server config");

            assert_that(&config).is_equal_to(expected);
        }

        #[test]
        fn tls_cloudflare_dns_com_tls_auth_name() {
            crate::utils::tests::logging::init();
            let str = "tls:cloudflare-dns.com,tls_auth_name=cloudflare-dns.com";
            let expected = NameServerConfig::new_with_tls_auth_name_and_name(
                Protocol::Tls,
                Target::Name("cloudflare-dns.com"),
                853,
                "cloudflare-dns.com",
                None,
            );

            let (_, config) = parsed_name_server_config(str).expect("failed to parse name server config");

            assert_that(&config).is_equal_to(expected);
        }

        #[test]
        fn tls_dns_google_tls_auth_name() {
            crate::utils::tests::logging::init();
            let str = "tls:dns.google,tls_auth_name=dns.google";
            let expected = NameServerConfig::new_with_tls_auth_name_and_name(
                Protocol::Tls,
                Target::Name("dns.google"),
                853,
                "dns.google",
                None,
            );

            let (_, config) = parsed_name_server_config(str).expect("failed to parse name server config");

            assert_that(&config).is_equal_to(expected);
        }

        #[test]
        fn tls_dns_google_port_tls_auth_name() {
            crate::utils::tests::logging::init();
            let str = "tls:dns.google:8853,tls_auth_name=dns.google";
            let expected = NameServerConfig::new_with_tls_auth_name_and_name(
                Protocol::Tls,
                Target::Name("dns.google"),
                8853,
                "dns.google",
                None,
            );

            let (_, config) = parsed_name_server_config(str).expect("failed to parse name server config");

            assert_that(&config).is_equal_to(expected);
        }

        #[test]
        fn tls_dns_google_port_tls_auth_name_name() {
            crate::utils::tests::logging::init();
            let str = "tls:dns.google:8853,tls_auth_name=dns.google,name=Google";
            let expected = NameServerConfig::new_with_tls_auth_name_and_name(
                Protocol::Tls,
                Target::Name("dns.google"),
                8853,
                "dns.google",
                "Google",
            );

            let (_, config) = parsed_name_server_config(str).expect("failed to parse name server config");

            assert_that(&config).is_equal_to(expected);
        }
    }
}
