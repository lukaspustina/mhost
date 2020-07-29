use thiserror::Error;

#[derive(Debug, Error)]
/// Main Error type of this crate.
///
/// Must be `Send` because it used by async function which might run on different threads.
pub enum Error {
    #[error("internal error: {msg}")]
    InternalError { msg: &'static str },
    #[error("resolver failed")]
    ResolverError {
        #[from]
        source: crate::resolver::Error,
    },
    #[error("failed to parse '{what}' to {to} because {why}")]
    ParserError {
        what: String,
        to: &'static str,
        why: String,
    },
    #[error("failed to execute IO operation for")]
    IoError {
        #[from]
        source: std::io::Error,
    },
    #[error("failed to serialize to JSON")]
    SerJsonError {
        #[from]
        source: serde_json::Error,
    },
}
