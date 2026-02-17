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
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::task::JoinError;

#[derive(Debug, Clone, Error, Serialize, Deserialize)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proto_timeout_maps_to_timeout() {
        let proto_err = ProtoError::from(ProtoErrorKind::Timeout);
        let err = Error::from(proto_err);
        assert!(matches!(err, Error::Timeout));
    }

    #[test]
    fn proto_request_refused_maps_to_query_refused() {
        let proto_err = ProtoError::from(ProtoErrorKind::RequestRefused);
        let err = Error::from(proto_err);
        assert!(matches!(err, Error::QueryRefused));
    }

    #[test]
    fn proto_no_records_servfail_maps_to_server_failure() {
        let proto_err = ProtoError::from(ProtoErrorKind::NoRecordsFound {
            query: Box::new(hickory_resolver::proto::op::Query::default()),
            soa: None,
            ns: None,
            negative_ttl: None,
            response_code: ResponseCode::ServFail,
            trusted: false,
            authorities: None,
        });
        let err = Error::from(proto_err);
        assert!(matches!(err, Error::ServerFailure));
    }

    #[test]
    fn proto_no_records_refused_maps_to_query_refused() {
        let proto_err = ProtoError::from(ProtoErrorKind::NoRecordsFound {
            query: Box::new(hickory_resolver::proto::op::Query::default()),
            soa: None,
            ns: None,
            negative_ttl: None,
            response_code: ResponseCode::Refused,
            trusted: false,
            authorities: None,
        });
        let err = Error::from(proto_err);
        assert!(matches!(err, Error::QueryRefused));
    }

    #[test]
    fn proto_no_records_nxdomain_maps_to_no_records_found() {
        let proto_err = ProtoError::from(ProtoErrorKind::NoRecordsFound {
            query: Box::new(hickory_resolver::proto::op::Query::default()),
            soa: None,
            ns: None,
            negative_ttl: None,
            response_code: ResponseCode::NXDomain,
            trusted: false,
            authorities: None,
        });
        let err = Error::from(proto_err);
        assert!(matches!(err, Error::NoRecordsFound));
    }

    #[test]
    fn proto_generic_error_maps_to_proto_error() {
        let proto_err = ProtoError::from("some generic error");
        let err = Error::from(proto_err);
        assert!(matches!(err, Error::ProtoError { .. }));
    }

    #[test]
    fn resolve_error_with_proto_delegates_to_proto_conversion() {
        let proto_err = ProtoError::from(ProtoErrorKind::Timeout);
        let resolve_err = ResolveError::from(proto_err);
        let err = Error::from(resolve_err);
        assert!(matches!(err, Error::Timeout));
    }

    #[test]
    fn resolve_error_non_proto_maps_to_resolve_error() {
        let resolve_err = ResolveError::from("some resolve error");
        let err = Error::from(resolve_err);
        assert!(matches!(err, Error::ResolveError { .. }));
    }

    #[tokio::test]
    async fn join_error_cancelled_maps_to_cancelled() {
        let handle = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            42
        });
        handle.abort();
        let join_err = handle.await.unwrap_err();
        let err = Error::from(join_err);
        assert!(matches!(err, Error::CancelledError));
    }

    #[test]
    fn error_display_messages() {
        assert_eq!(Error::Timeout.to_string(), "request timed out");
        assert_eq!(Error::QueryRefused.to_string(), "nameserver refused query");
        assert_eq!(
            Error::ServerFailure.to_string(),
            "nameserver responded with server failure"
        );
        assert_eq!(Error::NoRecordsFound.to_string(), "no records found");
        assert_eq!(Error::CancelledError.to_string(), "query has been cancelled");
        assert_eq!(Error::RuntimePanicError.to_string(), "query execution panicked");
    }
}
