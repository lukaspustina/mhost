mod cli;
mod config;
mod logging;
mod output;
mod resolver;
pub mod lookup;

pub use cli::*;
pub use config::{GlobalConfig, LookupConfig, SUPPORTED_OUTPUT_FORMATS, SUPPORTED_RECORD_TYPES};
pub use logging::start_logging_for_level;
pub use output::output;
pub use resolver::*;
