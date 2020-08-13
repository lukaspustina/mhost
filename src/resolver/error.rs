use lazy_static::lazy_static;
use serde::Serialize;
use thiserror::Error;
use tokio::task::JoinError;
use trust_dns_resolver::error::{ResolveError, ResolveErrorKind};
use trust_dns_resolver::proto::error::{ProtoError, ProtoErrorKind};
use trust_dns_resolver::proto::op::ResponseCode;

static TDR_NAMESERVER_RESPONDED_SERVFAIL: &str = "Nameserver responded with SERVFAIL";

lazy_static! {
    // cf. trust-dns-proto-0.19.5/src/op/response_code.rs:157
    // cf. trust-dns-resolver-0.19.5/src/lookup_state.rs:174
    pub static ref TDR_QUERY_REFUSED_MSG: String = {
        let query_refused = ResponseCode::Refused;
        format!("DNS Error: {}", query_refused)
    };
    // cf. trust-dns-resolver-0.19.5/src/name_server/name_server.rs:144
}

#[derive(Debug, Clone, Error, Serialize)]
pub enum Error {
    #[error("nameserver refused query")]
    QueryRefused,
    #[error("nameserver responded with server failure")]
    ServerFailure,
    #[error("request timed out")]
    Timeout,
    #[error("resolver error: {reason}")]
    ResolveError { reason: String },
    #[error("protocol error: {reason}")]
    ProtoError { reason: String },
    #[error("query has been cancelled")]
    CancelledError,
    #[error("query execution panicked")]
    RuntimePanicError,
}

impl From<ResolveError> for Error {
    fn from(error: trust_dns_resolver::error::ResolveError) -> Self {
        match &error.kind() {
            // Unfortunately, trust-dns-resolver does not provided types errors for some cases, so we have to look at the error msg
            ResolveErrorKind::Msg(msg) if *msg == *TDR_QUERY_REFUSED_MSG => Error::QueryRefused,
            ResolveErrorKind::Proto(proto_error) => Self::from(proto_error.clone()),
            ResolveErrorKind::Timeout => Error::Timeout,
            _ => Error::ResolveError {
                reason: error.to_string(),
            },
        }
    }
}

impl From<ProtoError> for Error {
    fn from(error: ProtoError) -> Self {
        match &error.kind() {
            // Unfortunately, trust-dns-resolver does not provided types errors for some cases, so we have to look at the error msg
            ProtoErrorKind::Message(msg) if *msg == TDR_NAMESERVER_RESPONDED_SERVFAIL => Error::ServerFailure,
            ProtoErrorKind::Timeout => Error::Timeout,
            _ => Error::ProtoError {
                reason: error.to_string(),
            },
        }
    }
}

impl From<JoinError> for Error {
    fn from(error: JoinError) -> Self {
        if error.is_cancelled() {
            return Error::CancelledError;
        }
        Error::RuntimePanicError
    }
}
