pub mod error;
pub mod ripe_stats;

pub use error::Error;

pub type Result<T> = std::result::Result<T, Error>;
