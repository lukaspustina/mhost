pub mod error;
pub mod lookup;
pub mod nameserver;
pub mod query;
pub mod resolver;
pub mod resources;
mod serialize;

pub use error::Error;
pub use query::{MultiQuery, Query};
pub use resources::RecordType;

pub use trust_dns_resolver::IntoName;
pub use trust_dns_resolver::Name;

pub type Result<T> = std::result::Result<T, error::Error>;
