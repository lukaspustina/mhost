// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! `mhost` is a modern, high-performance DNS lookup library and CLI tool.
//!
//! It provides multi-server concurrent DNS lookups across UDP, TCP, TLS (DoT), and HTTPS (DoH)
//! transports, with support for 20+ DNS record types. The library can query many nameservers in
//! parallel and aggregate results, making it well suited for DNS diagnostics, propagation checking,
//! and subdomain discovery.
//!
//! # Quick Start — Builder API
//!
//! The easiest way to get started is with [`ResolverGroupBuilder`](resolver::ResolverGroupBuilder):
//!
//! ```no_run
//! use mhost::resolver::{ResolverGroupBuilder, MultiQuery};
//! use mhost::resolver::lookup::Uniquify;
//! use mhost::nameserver::predefined::PredefinedProvider;
//! use mhost::RecordType;
//! use std::time::Duration;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Build a resolver group with system nameservers + Google DNS
//! let resolvers = ResolverGroupBuilder::new()
//!     .system()
//!     .predefined(PredefinedProvider::Google)
//!     .timeout(Duration::from_secs(3))
//!     .build()
//!     .await?;
//!
//! // Query for A and AAAA records
//! let query = MultiQuery::multi_record(
//!     "example.com",
//!     vec![RecordType::A, RecordType::AAAA],
//! )?;
//! let lookups = resolvers.lookup(query).await?;
//!
//! // Deduplicate results across nameservers
//! let a_records = lookups.a().unique().to_owned();
//! println!("A records: {:?}", a_records);
//! # Ok(())
//! # }
//! ```
//!
//! # Manual Construction
//!
//! For full control, you can construct resolvers manually:
//!
//! ```no_run
//! use mhost::nameserver::NameServerConfig;
//! use mhost::resolver::{MultiQuery, Resolver, ResolverConfig, ResolverGroup};
//! use mhost::resolver::lookup::Uniquify;
//! use mhost::RecordType;
//! use std::net::SocketAddr;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a ResolverGroup from the OS nameservers
//! let mut resolvers = ResolverGroup::from_system_config(Default::default())
//!     .await?;
//!
//! // Add a custom resolver for Google DNS
//! let sock_addr: SocketAddr = "8.8.8.8:53".parse()?;
//! let config = ResolverConfig::new(NameServerConfig::udp(sock_addr));
//! let google = Resolver::new(config, Default::default()).await?;
//! resolvers.add(google);
//!
//! // Lookup A, AAAA, and TXT records
//! let query = MultiQuery::multi_record(
//!     "example.com",
//!     vec![RecordType::A, RecordType::AAAA, RecordType::TXT],
//! )?;
//! let lookups = resolvers.lookup(query).await?;
//! let a_records = lookups.a().unique().to_owned();
//! println!("A records: {:?}", a_records);
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "app-lib")]
pub mod app;
pub mod diff;
pub mod error;
pub mod estimate;
pub mod nameserver;
pub mod resolver;
pub mod resources;
#[cfg(feature = "services")]
pub mod services;
pub mod statistics;
pub mod system_config;
pub mod utils;

pub use error::Error;
pub use ipnetwork::IpNetwork;
pub use resources::rdata::{IntoName, Name};
pub use resources::RecordType;

pub type Result<T> = std::result::Result<T, error::Error>;
