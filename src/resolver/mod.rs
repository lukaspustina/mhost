// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! DNS resolver abstractions for concurrent multi-server lookups.
//!
//! This module provides [`Resolver`] for querying a single nameserver and
//! [`ResolverGroup`] for fanning out queries across multiple nameservers concurrently.
//! Use [`ResolverGroupBuilder`] for ergonomic construction, or build resolvers manually
//! via [`ResolverGroup::from_configs`] and [`ResolverGroup::from_system_config`].
//!
//! Queries are expressed as [`UniQuery`] (single name + record type) or [`MultiQuery`]
//! (multiple names and/or record types). Results are returned as [`Lookups`], which
//! provides typed accessors (`.a()`, `.mx()`, `.txt()`, etc.) and deduplication via
//! the [`Uniquify`](lookup::Uniquify) trait.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures::future::join_all;
use futures::stream::{self, StreamExt};
use futures::Future;
use rand::seq::IndexedRandom;
use tokio::task;
use tracing::instrument;

pub use builder::ResolverGroupBuilder;
pub use error::Error;
pub use lookup::{Lookup, Lookups};
pub use query::{MultiQuery, UniQuery};

use crate::nameserver::{NameServerConfig, NameServerConfigGroup};
use crate::system_config;
use crate::Result;
use std::fmt::Display;
use std::fmt::Formatter;
use std::str::FromStr;

pub mod builder;
pub mod delegation;
pub mod error;
pub mod lookup;
pub mod predefined;
pub mod query;
pub mod raw;

pub type ResolverResult<T> = std::result::Result<T, Error>;

/// Configuration for a single [`Resolver`], wrapping a [`NameServerConfig`].
#[derive(Debug)]
pub struct ResolverConfig {
    name_server_config: NameServerConfig,
}

impl ResolverConfig {
    pub fn new(name_server_config: NameServerConfig) -> Self {
        ResolverConfig { name_server_config }
    }
}

impl From<NameServerConfig> for ResolverConfig {
    fn from(ns_config: NameServerConfig) -> Self {
        ResolverConfig {
            name_server_config: ns_config,
        }
    }
}

/// Per-resolver options controlling timeout, retries, and query behavior.
///
/// Defaults are suitable for most use cases. Use [`from_system_config`](Self::from_system_config)
/// to derive options from the operating system's resolver configuration.
#[derive(Debug, Clone)]
pub struct ResolverOpts {
    pub retries: usize,
    /// Maximum number of concurrent queries sent with this resolver.
    pub max_concurrent_requests: usize,
    pub ndots: usize,
    pub preserve_intermediates: bool,
    /// cf. `hickory_resolver::proto::xfer::DnsRequestOptions`
    pub expects_multiple_responses: bool,
    pub timeout: Duration,
    pub abort_on_error: bool,
    pub abort_on_timeout: bool,
}

impl ResolverOpts {
    /// Creates `ResolverOpts` from local system configuration.
    ///
    /// Unix: Parses `/etc/resolv.conf`.
    pub fn from_system_config() -> Result<ResolverOpts> {
        let opts = system_config::load_from_system_config()?;
        Ok(opts)
    }

    pub fn from_system_config_path<P: AsRef<Path>>(path: P) -> Result<ResolverOpts> {
        let opts = system_config::load_from_system_config_path(path)?;
        Ok(opts)
    }
}

impl Default for ResolverOpts {
    fn default() -> Self {
        ResolverOpts {
            retries: 1,
            max_concurrent_requests: 5,
            ndots: 1,
            preserve_intermediates: false,
            expects_multiple_responses: false,
            timeout: Duration::from_secs(5),
            abort_on_error: true,
            abort_on_timeout: true,
        }
    }
}

/// A collection of [`ResolverConfig`]s, typically used to create a [`ResolverGroup`].
#[derive(Debug)]
pub struct ResolverConfigGroup {
    configs: Vec<ResolverConfig>,
}

impl ResolverConfigGroup {
    pub fn new(resolver_configs: Vec<ResolverConfig>) -> ResolverConfigGroup {
        ResolverConfigGroup {
            configs: resolver_configs,
        }
    }

    /// Merges this `ResolverConfigGroup` with another
    pub fn merge(&mut self, other: Self) {
        self.configs.extend(other.configs)
    }
}

impl From<NameServerConfigGroup> for ResolverConfigGroup {
    fn from(configs: NameServerConfigGroup) -> Self {
        let resolver_confings: Vec<_> = configs.into_iter().map(From::from).collect();
        ResolverConfigGroup::new(resolver_confings)
    }
}

impl IntoIterator for ResolverConfigGroup {
    type Item = ResolverConfig;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.configs.into_iter()
    }
}

/// A DNS resolver bound to a single nameserver.
///
/// Wraps a [`hickory_resolver::TokioResolver`] and tracks the associated
/// [`NameServerConfig`] and [`ResolverOpts`]. Cloning is cheap (inner state is `Arc`-wrapped).
#[derive(Debug, Clone)]
pub struct Resolver {
    pub(crate) inner: Arc<hickory_resolver::TokioResolver>,
    pub(crate) opts: Arc<ResolverOpts>,
    pub(crate) name_server: Arc<NameServerConfig>,
}

impl Resolver {
    /// Creates a new Resolver.
    ///
    /// May panic if underlying tasks panic
    #[instrument(name =  "create resolver", level = "info", skip(config, opts), fields(server = %config.name_server_config))]
    pub async fn new(config: ResolverConfig, opts: ResolverOpts) -> ResolverResult<Self> {
        let name_server = config.name_server_config.clone();
        let tr_opts = opts.clone().into();
        let tr_config: hickory_resolver::config::ResolverConfig = config.into();
        let tr_resolver = hickory_resolver::Resolver::builder_with_config(
            tr_config,
            hickory_resolver::name_server::TokioConnectionProvider::default(),
        )
        .with_options(tr_opts)
        .build();

        Ok(Resolver {
            inner: Arc::new(tr_resolver),
            opts: Arc::new(opts),
            name_server: Arc::new(name_server),
        })
    }

    pub async fn lookup<T: Into<MultiQuery>>(&self, query: T) -> ResolverResult<Lookups> {
        lookup::lookup(self.clone(), query).await
    }

    pub fn name(&self) -> String {
        self.name_server.to_string()
    }
}

/// Group-level options for a [`ResolverGroup`].
#[derive(Debug, Clone)]
pub struct ResolverGroupOpts {
    /// Maximum number of resolvers queried concurrently.
    pub max_concurrent: usize,
    /// Optional limit on the number of resolvers used per query.
    pub limit: Option<usize>,
    /// Lookup mode: [`Multi`](Mode::Multi) fans out to all resolvers,
    /// [`Uni`](Mode::Uni) picks one at random per query.
    pub mode: Mode,
}

/// Lookup mode controlling how queries are distributed across resolvers.
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum Mode {
    /// Send each query to all available resolvers and aggregate results.
    Multi,
    /// Send each query to a single randomly chosen resolver.
    Uni,
}

impl Display for Mode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Mode::Multi => write!(f, "multi"),
            Mode::Uni => write!(f, "uni"),
        }
    }
}

impl FromStr for Mode {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "multi" => Ok(Mode::Multi),
            "uni" => Ok(Mode::Uni),
            _ => Err(crate::error::Error::ParserError {
                what: s.to_string(),
                to: "Mode",
                why: "no such mode".to_string(),
            }),
        }
    }
}

impl Default for ResolverGroupOpts {
    fn default() -> Self {
        ResolverGroupOpts {
            max_concurrent: 10,
            limit: None,
            mode: Mode::Multi,
        }
    }
}

/// A group of DNS [`Resolver`]s that fans out queries concurrently.
///
/// A `ResolverGroup` queries multiple nameservers in parallel and collects
/// the results into [`Lookups`]. Use [`ResolverGroupBuilder`] for ergonomic
/// construction, or create one directly via [`from_configs`](Self::from_configs)
/// or [`from_system_config`](Self::from_system_config).
#[derive(Debug)]
pub struct ResolverGroup {
    pub(crate) resolvers: Vec<Resolver>,
    pub(crate) opts: ResolverGroupOpts,
}

impl ResolverGroup {
    pub fn new<T: Into<Vec<Resolver>>>(resolvers: T, opts: ResolverGroupOpts) -> Self {
        ResolverGroup {
            resolvers: resolvers.into(),
            opts,
        }
    }

    pub async fn from_configs<T: IntoIterator<Item = ResolverConfig>>(
        configs: T,
        resolver_opts: ResolverOpts,
        opts: ResolverGroupOpts,
    ) -> Result<Self> {
        // Create resolver futures
        let futures: Vec<_> = configs
            .into_iter()
            .map(|config| Resolver::new(config, resolver_opts.clone()))
            .collect();

        // Wait all futures
        let resolvers: ResolverResult<Vec<_>> = join_all(futures).await.drain(..).collect();

        // Check for Err
        let resolvers = resolvers?;

        Ok(Self::new(resolvers, opts))
    }

    pub async fn from_system_config(opts: ResolverGroupOpts) -> Result<Self> {
        let resolver_opts = ResolverOpts::from_system_config()?;
        let configs: ResolverConfigGroup = NameServerConfigGroup::from_system_config()?.into();
        ResolverGroup::from_configs(configs, resolver_opts, opts).await
    }

    pub async fn lookup<T: Into<MultiQuery>>(&self, query: T) -> ResolverResult<Lookups> {
        match self.opts.mode {
            Mode::Multi => self.multi_lookup(query).await,
            Mode::Uni => self.uni_lookup(query).await,
        }
    }

    async fn multi_lookup<T: Into<MultiQuery>>(&self, query: T) -> ResolverResult<Lookups> {
        let multi_query = query.into();
        let mut resolvers = self.resolvers.clone();

        let lookup_futures: Vec<_> = resolvers
            .drain(..)
            .take(self.opts.limit.unwrap_or(self.resolvers.len()))
            .map(|resolver| lookup::lookup(resolver, multi_query.clone()))
            .collect();
        let lookups = sliding_window_lookups(lookup_futures, self.opts.max_concurrent);
        let lookups = task::spawn(lookups).await?;

        Ok(lookups)
    }

    async fn uni_lookup<T: Into<MultiQuery>>(&self, query: T) -> ResolverResult<Lookups> {
        if self.resolvers.is_empty() {
            return Err(Error::ResolveError {
                reason: "no resolvers available".to_string(),
            });
        }

        let mut rng = rand::rng();
        let multi_query = query.into();
        let resolvers = self.resolvers.as_slice();

        let lookup_futures: Vec<_> = multi_query
            .into_uni_queries()
            .drain(..)
            .map(|q| {
                let resolver = resolvers.choose(&mut rng).expect("resolvers is non-empty");
                lookup::lookup(resolver.clone(), q)
            })
            .collect();
        let lookups = sliding_window_lookups(lookup_futures, self.opts.max_concurrent);
        let lookups = task::spawn(lookups).await?;

        Ok(lookups)
    }

    /// Merges this `ResolverGroup` with another
    ///
    /// Attention: the `ResolverGroupOpts` of this `ResolverGroup` will apply
    pub fn merge(&mut self, other: Self) {
        self.resolvers.extend(other.resolvers)
    }

    pub fn add(&mut self, resolver: Resolver) {
        self.resolvers.push(resolver)
    }

    pub fn set_opts(&mut self, opts: ResolverGroupOpts) {
        self.opts = opts
    }

    pub fn opts(&self) -> &ResolverGroupOpts {
        &self.opts
    }

    pub fn resolvers(&self) -> &[Resolver] {
        self.resolvers.as_slice()
    }

    pub fn len(&self) -> usize {
        self.resolvers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.resolvers.is_empty()
    }
}

async fn sliding_window_lookups(
    futures: Vec<impl Future<Output = ResolverResult<Lookups>>>,
    max_concurrent: usize,
) -> Lookups {
    #[allow(clippy::map_flatten)]
    stream::iter(futures)
        .buffer_unordered(max_concurrent)
        .collect::<Vec<_>>()
        .await
        .drain(..)
        // This map and the consecutive flatten mask JoinErrors which occurred during the lookups. This is a conscious decision!
        // It doesn't make sense to panic (library wouldn't be resilient anymore), return _one_ error and abort by collecting the Vec
        // what would be the semantic of that -- why to bother with catching errors in the first place in lookup.
        // So the only reasonable way is to ignore the errors or return Vec<Result<>>
        .map(|l| l.ok())
        .flatten()
        .flatten()
        .collect::<Vec<_>>()
        .into()
}

#[doc(hidden)]
impl From<resolv_conf::Config> for ResolverOpts {
    fn from(config: resolv_conf::Config) -> Self {
        ResolverOpts {
            retries: config.attempts as usize,
            ndots: config.ndots as usize,
            timeout: Duration::from_secs(config.timeout as u64),
            ..Default::default()
        }
    }
}

#[doc(hidden)]
impl From<ResolverOpts> for hickory_resolver::config::ResolverOpts {
    fn from(opts: ResolverOpts) -> Self {
        let mut resolver_opts = hickory_resolver::config::ResolverOpts::default();
        resolver_opts.attempts = opts.retries;
        resolver_opts.ndots = opts.ndots;
        resolver_opts.num_concurrent_reqs = opts.max_concurrent_requests;
        resolver_opts.preserve_intermediates = opts.preserve_intermediates;
        resolver_opts.timeout = opts.timeout;
        resolver_opts
    }
}

#[cfg(test)]
impl Resolver {
    pub fn new_for_test(opts: ResolverOpts, name_server: NameServerConfig) -> Self {
        let config = ResolverConfig::new(name_server.clone());
        let tr_opts: hickory_resolver::config::ResolverOpts = opts.clone().into();
        let tr_config: hickory_resolver::config::ResolverConfig = config.into();
        let tr_resolver = hickory_resolver::Resolver::builder_with_config(
            tr_config,
            hickory_resolver::name_server::TokioConnectionProvider::default(),
        )
        .with_options(tr_opts)
        .build();

        Resolver {
            inner: Arc::new(tr_resolver),
            opts: Arc::new(opts),
            name_server: Arc::new(name_server),
        }
    }
}

#[doc(hidden)]
impl From<ResolverConfig> for hickory_resolver::config::ResolverConfig {
    fn from(rc: ResolverConfig) -> Self {
        let mut config = Self::new();
        config.add_name_server(rc.name_server_config.into());

        config
    }
}
