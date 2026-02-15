// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Fluent builder for constructing a [`ResolverGroup`].
//!
//! The builder accumulates nameserver sources and configuration options,
//! deferring all I/O (e.g., reading `/etc/resolv.conf`) to the async
//! [`build`](ResolverGroupBuilder::build) method.
//!
//! # Example
//! ```no_run
//! use mhost::resolver::ResolverGroupBuilder;
//! use mhost::nameserver::predefined::PredefinedProvider;
//! use std::time::Duration;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let resolvers = ResolverGroupBuilder::new()
//!     .system()
//!     .predefined(PredefinedProvider::Google)
//!     .timeout(Duration::from_secs(3))
//!     .build()
//!     .await?;
//! # Ok(())
//! # }
//! ```

use std::time::Duration;

use crate::nameserver::predefined::PredefinedProvider;
use crate::nameserver::{NameServerConfig, NameServerConfigGroup};
use crate::resolver::{Mode, ResolverConfigGroup, ResolverGroup, ResolverGroupOpts, ResolverOpts};
use crate::Result;

/// Accumulated nameserver source, resolved at build time.
#[derive(Debug)]
enum NameServerSource {
    /// Load nameservers from the operating system's resolver configuration.
    System,
    /// Use all nameservers from a predefined public DNS provider.
    Predefined(PredefinedProvider),
    /// A single custom nameserver configuration.
    Custom(NameServerConfig),
}

/// A fluent builder for constructing a [`ResolverGroup`].
///
/// Accumulates nameserver sources and per-resolver / group-level options.
/// All I/O is deferred until [`build`](Self::build) is called.
///
/// Uses a consume-self pattern: each method takes `self` by value and returns `Self`,
/// preventing use after [`build`](Self::build).
#[derive(Debug)]
pub struct ResolverGroupBuilder {
    sources: Vec<NameServerSource>,
    resolver_opts: Option<ResolverOpts>,
    group_opts: Option<ResolverGroupOpts>,
    // Individual overrides applied on top of base opts:
    timeout: Option<Duration>,
    retries: Option<usize>,
    max_concurrent_requests: Option<usize>,
    max_concurrent_servers: Option<usize>,
    limit: Option<usize>,
    mode: Option<Mode>,
}

impl ResolverGroupBuilder {
    /// Creates a new empty builder.
    pub fn new() -> Self {
        ResolverGroupBuilder {
            sources: Vec::new(),
            resolver_opts: None,
            group_opts: None,
            timeout: None,
            retries: None,
            max_concurrent_requests: None,
            max_concurrent_servers: None,
            limit: None,
            mode: None,
        }
    }

    /// Add the operating system's nameservers (from `/etc/resolv.conf` on Unix).
    ///
    /// Multiple calls are deduplicated — system nameservers are loaded at most once.
    /// This only adds nameservers; resolver options are not loaded from system config.
    /// To also use system resolver options, call
    /// `.resolver_opts(ResolverOpts::from_system_config()?)`.
    pub fn system(mut self) -> Self {
        if !self.sources.iter().any(|s| matches!(s, NameServerSource::System)) {
            self.sources.push(NameServerSource::System);
        }
        self
    }

    /// Add all nameservers from a predefined public DNS provider.
    pub fn predefined(mut self, provider: PredefinedProvider) -> Self {
        self.sources.push(NameServerSource::Predefined(provider));
        self
    }

    /// Add all nameservers from all predefined providers.
    pub fn all_predefined(mut self) -> Self {
        for provider in PredefinedProvider::all() {
            self.sources.push(NameServerSource::Predefined(*provider));
        }
        self
    }

    /// Add a single custom nameserver.
    pub fn nameserver(mut self, config: NameServerConfig) -> Self {
        self.sources.push(NameServerSource::Custom(config));
        self
    }

    /// Add multiple custom nameservers.
    pub fn nameservers(mut self, configs: impl IntoIterator<Item = NameServerConfig>) -> Self {
        for config in configs {
            self.sources.push(NameServerSource::Custom(config));
        }
        self
    }

    /// Set the per-query timeout for each resolver.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the number of retries per query for each resolver.
    pub fn retries(mut self, retries: usize) -> Self {
        self.retries = Some(retries);
        self
    }

    /// Set the maximum number of concurrent requests per resolver.
    pub fn max_concurrent_requests(mut self, max: usize) -> Self {
        self.max_concurrent_requests = Some(max);
        self
    }

    /// Set the maximum number of concurrently active resolvers in the group.
    pub fn max_concurrent_servers(mut self, max: usize) -> Self {
        self.max_concurrent_servers = Some(max);
        self
    }

    /// Limit the number of resolvers used for each query.
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set the lookup mode (multi or uni).
    pub fn mode(mut self, mode: Mode) -> Self {
        self.mode = Some(mode);
        self
    }

    /// Set base per-resolver options. Individual overrides (e.g., [`timeout`](Self::timeout))
    /// are applied on top of these.
    pub fn resolver_opts(mut self, opts: ResolverOpts) -> Self {
        self.resolver_opts = Some(opts);
        self
    }

    /// Set base group-level options. Individual overrides (e.g., [`max_concurrent_servers`](Self::max_concurrent_servers))
    /// are applied on top of these.
    pub fn group_opts(mut self, opts: ResolverGroupOpts) -> Self {
        self.group_opts = Some(opts);
        self
    }

    /// Resolve all accumulated sources and create the [`ResolverGroup`].
    ///
    /// This method performs I/O: it reads system resolver configuration if
    /// [`system`](Self::system) was called, and creates async resolver instances.
    pub async fn build(self) -> Result<ResolverGroup> {
        // Materialize all NameServerConfigs from sources
        let mut configs = Vec::new();
        for source in self.sources {
            match source {
                NameServerSource::System => {
                    let system_configs = NameServerConfigGroup::from_system_config()?;
                    configs.extend(system_configs);
                }
                NameServerSource::Predefined(provider) => {
                    configs.extend(provider.configs());
                }
                NameServerSource::Custom(config) => {
                    configs.push(config);
                }
            }
        }

        // Build resolver opts: start from base, apply overrides
        let mut resolver_opts = self.resolver_opts.unwrap_or_default();
        if let Some(timeout) = self.timeout {
            resolver_opts.timeout = timeout;
        }
        if let Some(retries) = self.retries {
            resolver_opts.retries = retries;
        }
        if let Some(max) = self.max_concurrent_requests {
            resolver_opts.max_concurrent_requests = max;
        }

        // Build group opts: start from base, apply overrides
        let mut group_opts = self.group_opts.unwrap_or_default();
        if let Some(max) = self.max_concurrent_servers {
            group_opts.max_concurrent = max;
        }
        if let Some(limit) = self.limit {
            group_opts.limit = Some(limit);
        }
        if let Some(mode) = self.mode {
            group_opts.mode = mode;
        }

        // Convert to ResolverConfigs and build group
        let resolver_configs: ResolverConfigGroup = crate::nameserver::NameServerConfigGroup::new(configs).into();
        ResolverGroup::from_configs(resolver_configs, resolver_opts, group_opts).await
    }
}

impl Default for ResolverGroupBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn builder_default_is_empty() {
        let builder = ResolverGroupBuilder::new();
        assert!(builder.sources.is_empty());
        assert!(builder.resolver_opts.is_none());
        assert!(builder.group_opts.is_none());
        assert!(builder.timeout.is_none());
    }

    #[test]
    fn builder_accumulates_sources() {
        let builder = ResolverGroupBuilder::new()
            .predefined(PredefinedProvider::Google)
            .nameserver(NameServerConfig::udp((Ipv4Addr::new(1, 1, 1, 1), 53)));
        assert_eq!(builder.sources.len(), 2);
    }

    #[test]
    fn builder_system_deduplicates() {
        let builder = ResolverGroupBuilder::new().system().system().system();
        let system_count = builder
            .sources
            .iter()
            .filter(|s| matches!(s, NameServerSource::System))
            .count();
        assert_eq!(system_count, 1);
    }

    #[test]
    fn builder_all_predefined_adds_six() {
        let builder = ResolverGroupBuilder::new().all_predefined();
        let predefined_count = builder
            .sources
            .iter()
            .filter(|s| matches!(s, NameServerSource::Predefined(_)))
            .count();
        assert_eq!(predefined_count, 6);
    }

    #[test]
    fn builder_option_overrides() {
        let builder = ResolverGroupBuilder::new()
            .timeout(Duration::from_secs(10))
            .retries(3)
            .max_concurrent_servers(20)
            .limit(5)
            .mode(Mode::Uni);
        assert_eq!(builder.timeout, Some(Duration::from_secs(10)));
        assert_eq!(builder.retries, Some(3));
        assert_eq!(builder.max_concurrent_servers, Some(20));
        assert_eq!(builder.limit, Some(5));
        assert_eq!(builder.mode, Some(Mode::Uni));
    }

    #[tokio::test]
    async fn build_empty_produces_empty_group() {
        let group = ResolverGroupBuilder::new().build().await.unwrap();
        assert!(group.is_empty());
    }

    #[tokio::test]
    async fn build_with_custom_nameserver() {
        let group = ResolverGroupBuilder::new()
            .nameserver(NameServerConfig::udp((Ipv4Addr::new(8, 8, 8, 8), 53)))
            .build()
            .await
            .unwrap();
        assert_eq!(group.len(), 1);
    }

    #[tokio::test]
    async fn build_with_predefined_provider() {
        let expected_count = PredefinedProvider::Google.configs().len();
        let group = ResolverGroupBuilder::new()
            .predefined(PredefinedProvider::Google)
            .build()
            .await
            .unwrap();
        assert_eq!(group.len(), expected_count);
    }

    #[tokio::test]
    async fn build_applies_option_overrides() {
        let group = ResolverGroupBuilder::new()
            .nameserver(NameServerConfig::udp((Ipv4Addr::new(8, 8, 8, 8), 53)))
            .max_concurrent_servers(42)
            .limit(7)
            .mode(Mode::Uni)
            .build()
            .await
            .unwrap();
        assert_eq!(group.opts().max_concurrent, 42);
        assert_eq!(group.opts().limit, Some(7));
        assert_eq!(group.opts().mode, Mode::Uni);
    }

    #[tokio::test]
    async fn build_option_overrides_on_base_opts() {
        let base = ResolverOpts {
            timeout: Duration::from_secs(1),
            retries: 1,
            ..Default::default()
        };
        let group = ResolverGroupBuilder::new()
            .nameserver(NameServerConfig::udp((Ipv4Addr::new(8, 8, 8, 8), 53)))
            .resolver_opts(base)
            .timeout(Duration::from_secs(99))
            .build()
            .await
            .unwrap();
        // The resolver was created with the overridden timeout
        let resolver = &group.resolvers()[0];
        assert_eq!(resolver.opts.timeout, Duration::from_secs(99));
        // Retries should remain from the base
        assert_eq!(resolver.opts.retries, 1);
    }
}
