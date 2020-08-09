use thiserror::Error;
use tokio::task::JoinError;

#[derive(Debug, Error)]
pub enum Error {
    #[error("HTTP client error: {why}")]
    HttpClientError { why: &'static str, source: reqwest::Error },
    #[error("HTTP client error: {why}")]
    HttpClientErrorMessage { why: &'static str, details: String },
    #[error("failed to deserialize")]
    DeserializationError {
        #[from]
        source: serde_json::error::Error,
    },
    #[error("execution has been cancelled")]
    CancelledError,
    #[error("execution panicked")]
    RuntimePanicError,
}

impl From<JoinError> for Error {
    fn from(error: JoinError) -> Self {
        if error.is_cancelled() {
            return Error::CancelledError;
        }
        Error::RuntimePanicError
    }
}
