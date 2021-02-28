// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! mhost is a modern take on the classic host DNS lookup utility including an easy to use, and very fast Rust library.
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
