use thiserror::Error;

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
}
