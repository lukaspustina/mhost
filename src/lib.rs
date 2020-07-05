pub mod error;
pub use error::Error;
pub mod lookup;
pub mod nameserver;
pub mod resolver;

pub use trust_dns_resolver::proto::rr::RecordType;

type Result<T> = std::result::Result<T, error::Error>;
