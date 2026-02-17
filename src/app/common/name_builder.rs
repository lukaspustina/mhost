// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::{IntoName, Name};
use anyhow::{Context, Result};

pub struct NameBuilderOpts {
    ndots: u8,
    search_domain: Name,
}

impl NameBuilderOpts {
    pub fn new<T: IntoName>(ndots: u8, search_domain: T) -> Result<Self> {
        let search_domain = search_domain
            .into_name()
            .context("failed to parse search domain name")?;
        Ok(NameBuilderOpts { ndots, search_domain })
    }

    /// Creates a new `NameBuilderOpts` by using the domain name from the local host's hostname as search domain.
    #[cfg(feature = "hostname")]
    pub fn from_hostname(ndots: u8) -> Result<Self> {
        use std::str::FromStr;
        let hostname = hostname::get()
            .context("failed to get local hostname")?
            .to_string_lossy()
            .to_string();
        let name = Name::from_str(&hostname).context("failed to parse local hostname")?;
        let search_domain = name.base_name();
        NameBuilderOpts::new(ndots, search_domain)
    }
}

impl Default for NameBuilderOpts {
    fn default() -> Self {
        NameBuilderOpts::new(1, Name::root()).unwrap()
    }
}

/** NameBuilder offers a safe way to transform a string into a `Name`.
 *
 * `NameBuilder` takes the search domain into account by checking `ndots` to qualify a name as FQDN or not.
 */
pub struct NameBuilder {
    config: NameBuilderOpts,
}

impl NameBuilder {
    pub fn new(config: NameBuilderOpts) -> NameBuilder {
        NameBuilder { config }
    }

    /// Creates a `Name` from a &str.
    ///
    /// In case the given name has less or equal lables (dots) as configures by `NameBuilderConfig::ndots` the search
    /// domain `NameBuilderConfig::search_domain` is added to resulting `Name`.
    ///
    /// Example:
    /// ```
    /// # use mhost::app::common::name_builder::{NameBuilderOpts, NameBuilder};
    /// # use mhost::Name;
    /// let config = NameBuilderOpts::new(1, "example.com").unwrap();
    /// let builder = NameBuilder::new(config);
    /// let name = builder.from_str("www").unwrap();
    /// assert_eq!(name, Name::from_ascii("www.example.com.").unwrap())
    /// ```
    pub fn from_str(&self, name: &str) -> Result<Name> {
        let mut domain_name: Name = name.into_name().context("failed to parse domain name")?;
        let domain_name = if domain_name.num_labels() > self.config.ndots {
            domain_name.set_fqdn(true);
            domain_name
        } else {
            domain_name.append_domain(&self.config.search_domain)?
        };

        Ok(domain_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_builder_1ndots_0dot() {
        let config = NameBuilderOpts::new(1, "example.com").unwrap();
        let builder = NameBuilder::new(config);
        let name = builder.from_str("www").unwrap();

        assert_eq!(name, Name::from_ascii("www.example.com.").unwrap())
    }

    #[test]
    fn name_builder_1ndots_1dot() {
        let config = NameBuilderOpts::new(1, "example.com").unwrap();
        let builder = NameBuilder::new(config);
        let name = builder.from_str("www.").unwrap();

        assert_eq!(name, Name::from_ascii("www.example.com.").unwrap())
    }

    #[test]
    fn name_builder_1ndots_1dot_2lables() {
        let config = NameBuilderOpts::new(1, "example.com").unwrap();
        let builder = NameBuilder::new(config);
        let name = builder.from_str("www.test").unwrap();

        assert_eq!(name, Name::from_ascii("www.test.").unwrap())
    }

    #[test]
    fn name_builder_1ndots_1dot_3lables() {
        let config = NameBuilderOpts::new(1, "example.com").unwrap();
        let builder = NameBuilder::new(config);
        let name = builder.from_str("www.test.com").unwrap();

        assert_eq!(name, Name::from_ascii("www.test.com.").unwrap())
    }
}
