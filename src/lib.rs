// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

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
