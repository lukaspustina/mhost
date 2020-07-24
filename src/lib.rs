pub mod diff;
pub mod error;
pub mod estimate;
pub mod nameserver;
pub mod output;
pub mod resolver;
pub mod resources;
mod serialize;
pub mod statistics;
pub mod system_config;

pub use error::Error;
pub use resources::rdata::{IntoName, Name};
pub use resources::RecordType;
pub use ipnetwork::IpNetwork;

pub type Result<T> = std::result::Result<T, error::Error>;
