pub mod error;
pub mod server_lists;
pub mod whois;

pub use error::Error;

pub type Result<T> = std::result::Result<T, Error>;
