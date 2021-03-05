// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! `mhost` is a modern take on the classic `host` DNS lookup utility including an easy to use, and very fast Rust library.
//!
//! The library is currently still in a PoC state. It works and the command line tool `mhost`
//! already uses it. Nevertheless, I'm not satisfied with the design and architecture so it is
//! still work in progress.
//!
//! Unfortunately, this also means that the library totally lacks documentation. If you want to use
//! the library in your own project, please be aware that the API might change. Even though
//! documentation is missing, you can find fully working examples that might help to jump start
//! you.
//!
//! Please feel free to give me feedback in form of GitHub issues and I welcome any PRs.
//!
//! # Example
//! Lookup A, AAAA, and TXT records for `mhost.pustina.de` using the local operating system's nameservers as
//! well as Google's nameserver.
//! ```
//! use mhost::nameserver::NameServerConfig;
//! use mhost::resolver::{MultiQuery, Resolver, ResolverConfig, ResolverGroup};
//! use mhost::resolver::lookup::Uniquify;
//! use mhost::statistics::Statistics;
//! use mhost::RecordType;
//! use std::net::SocketAddr;
//!
//! # #[tokio::main]
//! # async fn main() {
//! #
//! // Create a `ResolverGroup` with operating system's nameservers; a `ResolverGroup`
//! // acts the same a single `Resolver` and allows to lookup records from multiple name servers.
//! let mut resolvers = ResolverGroup::from_system_config(Default::default())
//!      .await
//!      .expect("failed to create system resolvers");
//!
//! // Create a Resolver for Google's DNS nameserver with UDP transport
//! let sock_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
//! let name_server_config = NameServerConfig::udp(sock_addr);
//! let config = ResolverConfig::new(name_server_config);
//! let google = Resolver::new(config, Default::default())
//!     .await
//!     .expect("Failed to create Google resolver");
//!
//! // Add Google resolver to `ResolverGroup`
//! resolvers.add(google);
//!
//! // Prepare a `MultiQuery`: Query multiple names and/or multiple record types at once
//! let query = MultiQuery::multi_record(
//!     "mhost.pustina.de",
//!     vec![RecordType::A, RecordType::AAAA, RecordType::TXT]
//! ).expect("Failed to create query");
//!
//! // Perform multi-lookup
//! let lookups = resolvers.lookup(query).await.expect("Failed to execute lookups");
//!
//! // Print statistics about lookup results
//! println!("Statistics: {:#?}", lookups.statistics());
//!
//! // Print all results
//! println!("Multi-Lookup results: {:#?}", lookups);
//!
//! // Aggregate all A records
//! let a_records = lookups.a().unique().to_owned();
//! println!("A records: {:#?}", a_records);
//!
//! # assert!(a_records.len() > 0);
//! # }
//! ```

#[cfg(feature = "app")]
pub mod app;
pub mod diff;
pub mod error;
pub mod estimate;
pub mod nameserver;
pub mod resolver;
pub mod resources;
pub mod services;
pub mod statistics;
pub mod system_config;
pub mod utils;

pub use error::Error;
pub use ipnetwork::IpNetwork;
pub use resources::rdata::{IntoName, Name};
pub use resources::RecordType;

pub type Result<T> = std::result::Result<T, error::Error>;
