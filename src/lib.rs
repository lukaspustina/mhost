#[cfg(feature = "bin")]
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
