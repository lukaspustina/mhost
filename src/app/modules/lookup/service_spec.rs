// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use anyhow::{anyhow, Result};
use nom::Err;

#[derive(Debug, PartialEq, Eq)]
pub struct ServiceSpec {
    service_name: String,
    protocol: String,
    domain_name: String,
}

impl ServiceSpec {
    pub(crate) fn new<S: Into<String>, T: Into<String>, U: Into<String>>(
        service_name: S,
        protocol: T,
        domain_name: U,
    ) -> ServiceSpec {
        ServiceSpec {
            service_name: service_name.into(),
            protocol: protocol.into(),
            domain_name: domain_name.into(),
        }
    }

    pub fn to_domain_name(&self) -> String {
        format!("_{}._{}.{}", &self.service_name, &self.protocol, &self.domain_name)
    }
}

#[allow(clippy::should_implement_trait)]
impl ServiceSpec {
    pub fn from_str(str: &str) -> Result<ServiceSpec> {
        match parser::parse_service_spec(str) {
            Ok((_, result)) => Ok(result),
            Err(Err::Incomplete(_)) => Err(anyhow!(
                "failed to parse service spec '{}' because input is incomplete",
                str
            )),
            Err(Err::Error((_, why))) | Err(Err::Failure((_, why))) => Err(anyhow!(
                "failed to parse service spec '{}' because {}",
                str,
                why.description().to_string()
            )),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use spectral::prelude::*;

    #[test]
    fn smtp_tcp_example_com() {
        crate::utils::tests::logging::init();
        let str = "smtp:tcp:example.com";
        let expected = ServiceSpec::new("smtp", "tcp", "example.com");

        let spec = ServiceSpec::from_str(&str);

        assert_that(&spec).is_ok().is_equal_to(&expected);
    }

    #[test]
    #[allow(non_snake_case)]
    fn smtp___example_com() {
        crate::utils::tests::logging::init();
        let str = "smtp::example.com";
        let expected = ServiceSpec::new("smtp", "tcp", "example.com");

        let spec = ServiceSpec::from_str(&str);

        assert_that(&spec).is_ok().is_equal_to(&expected);
    }
}

#[allow(clippy::module_inception)]
pub(crate) mod parser {
    use nom::bytes::complete::{tag, take_while};
    use nom::IResult;

    use super::ServiceSpec;

    pub(crate) fn parse_service_spec(input: &str) -> IResult<&str, ServiceSpec> {
        let (input, service) = service(input)?;
        let (input, protocol) = protocol(input)?;
        let (input, domain) = domain(input)?;

        let protocol = if protocol.is_empty() { "tcp" } else { protocol };

        let spec = ServiceSpec::new(service, protocol, domain);

        Ok((input, spec))
    }

    fn service(input: &str) -> IResult<&str, &str> {
        let (input, str) = take_while(|c: char| c.is_alphanumeric() || c == '-')(input)?;

        Ok((input, str))
    }

    fn protocol(input: &str) -> IResult<&str, &str> {
        let (input, _) = tag(":")(input)?;
        let (input, str) = take_while(|c: char| c.is_alphanumeric() || c == '.' || c == '-')(input)?;

        Ok((input, str))
    }

    fn domain(input: &str) -> IResult<&str, &str> {
        let (input, _) = tag(":")(input)?;
        let (input, str) = take_while(|c: char| c.is_alphanumeric() || c == '.' || c == '-')(input)?;

        Ok((input, str))
    }
}
