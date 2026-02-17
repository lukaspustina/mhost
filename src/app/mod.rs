// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! `mhost` command line app to query, discover and lint DNS.

pub mod common;

#[cfg(feature = "app-tui")]
pub mod mdive;
#[cfg(feature = "app-cli")]
pub mod mhost;

// Re-exports for backward compatibility — keep existing `crate::app::*` paths working.
#[cfg(feature = "app-cli")]
pub use mhost::app_config;
#[cfg(feature = "app-cli")]
pub use mhost::cli_parser;
#[cfg(feature = "app-cli")]
pub use mhost::console;
#[cfg(feature = "app-cli")]
pub use mhost::logging;
#[cfg(feature = "app-cli")]
pub use mhost::modules;
#[cfg(feature = "app-cli")]
pub use mhost::output;
#[cfg(feature = "app-cli")]
pub use mhost::resolver;
#[cfg(feature = "app-cli")]
pub use mhost::utils;
#[cfg(feature = "app-cli")]
pub use mhost::AppConfig;
#[cfg(feature = "app-cli")]
pub use mhost::ExitStatus;
