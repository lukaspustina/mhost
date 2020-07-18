pub mod error;
pub mod nameserver;
pub mod resolver;
pub mod resources;
mod serialize;
pub mod statistics;
pub mod system_config;

pub use error::Error;
pub use resources::RecordType;

pub use trust_dns_resolver::IntoName;
pub use trust_dns_resolver::Name;

pub type Result<T> = std::result::Result<T, error::Error>;
