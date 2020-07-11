pub mod error;
pub mod lookup;
pub mod nameserver;
pub mod query;
pub mod resolver;

pub use error::Error;
pub use query::{MultiQuery, Query};

pub use trust_dns_resolver::proto::rr::RecordType;
pub use trust_dns_resolver::IntoName;
pub use trust_dns_resolver::Name;

type Result<T> = std::result::Result<T, error::Error>;
