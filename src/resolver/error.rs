// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Resolver-specific error types.
//!
//! [`enum@Error`] classifies DNS failures into structured variants such as
//! [`Timeout`](Error::Timeout), [`QueryRefused`](Error::QueryRefused), and
//! [`ServerFailure`](Error::ServerFailure), making it easy to handle specific
//! failure modes programmatically.

use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::{ProtoError, ProtoErrorKind};
use hickory_resolver::{ResolveError, ResolveErrorKind};
use serde::Serialize;
use thiserror::Error;
use tokio::task::JoinError;

#[derive(Debug, Clone, Error, Serialize)]
pub enum Error {
    #[error("nameserver refused query")]
    QueryRefused,
    #[error("nameserver responded with server failure")]
    ServerFailure,
    #[error("request timed out")]
    Timeout,
    #[error("no records found")]
    NoRecordsFound,
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
    fn from(error: ResolveError) -> Self {
        match error.kind() {
            ResolveErrorKind::Proto(proto_error) => Self::from(proto_error.clone()),
            _ => Error::ResolveError {
                reason: error.to_string(),
            },
        }
    }
}

impl From<ProtoError> for Error {
    fn from(error: ProtoError) -> Self {
        match error.kind() {
            ProtoErrorKind::Timeout => Error::Timeout,
            ProtoErrorKind::RequestRefused => Error::QueryRefused,
            ProtoErrorKind::NoRecordsFound {
                response_code: ResponseCode::ServFail,
                ..
            } => Error::ServerFailure,
            ProtoErrorKind::NoRecordsFound {
                response_code: ResponseCode::Refused,
                ..
            } => Error::QueryRefused,
            ProtoErrorKind::NoRecordsFound { .. } => Error::NoRecordsFound,
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
