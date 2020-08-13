use crate::utils::serialize::ser_to_string;
use serde::Serialize;
use thiserror::Error;
use tokio::task::JoinError;

#[derive(Debug, Serialize, Error)]
pub enum Error {
    #[error("HTTP client error: {why}")]
    HttpClientError {
        why: &'static str,
        #[serde(serialize_with = "ser_to_string")]
        source: reqwest::Error,
    },
    #[error("HTTP client error: {why}")]
    HttpClientErrorMessage { why: &'static str, details: String },
    #[error("failed to deserialize")]
    DeserializationError {
        #[from]
        #[serde(serialize_with = "ser_to_string")]
        source: serde_json::error::Error,
    },
    #[error("failed to parse '{what}' to {to} because {why}")]
    ParserError {
        what: String,
        to: &'static str,
        why: String,
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
