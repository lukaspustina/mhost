pub mod error;
pub mod whois;

pub use error::Error;

pub type Result<T> = std::result::Result<T, Error>;
