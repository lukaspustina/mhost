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

use hickory_resolver::net::{DnsError, NetError, NoRecords};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::ProtoError;
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

impl Error {
    pub(crate) fn from_net(error: NetError) -> Self {
        match error {
            NetError::Timeout => Error::Timeout,
            NetError::Dns(DnsError::ResponseCode(ResponseCode::Refused)) => Error::QueryRefused,
            NetError::Dns(DnsError::ResponseCode(ResponseCode::ServFail)) => Error::ServerFailure,
            NetError::Dns(DnsError::NoRecordsFound(NoRecords {
                response_code: ResponseCode::ServFail,
                ..
            })) => Error::ServerFailure,
            NetError::Dns(DnsError::NoRecordsFound(NoRecords {
                response_code: ResponseCode::Refused,
                ..
            })) => Error::QueryRefused,
            NetError::Dns(DnsError::NoRecordsFound(_)) => Error::NoRecordsFound,
            NetError::Proto(proto_error) => Self::from_proto(proto_error),
            _ => Error::ResolveError {
                reason: error.to_string(),
            },
        }
    }
}

impl Error {
    pub(crate) fn from_proto(error: ProtoError) -> Self {
        Error::ProtoError {
            reason: error.to_string(),
        }
    }
}

impl From<crate::NameError> for Error {
    fn from(error: crate::NameError) -> Self {
        Error::ProtoError {
            reason: error.to_string(),
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
    fn net_timeout_maps_to_timeout() {
        let err = Error::from_net(NetError::Timeout);
        assert!(matches!(err, Error::Timeout));
    }

    #[test]
    fn response_code_refused_maps_to_query_refused() {
        let err = Error::from_net(NetError::Dns(DnsError::ResponseCode(ResponseCode::Refused)));
        assert!(matches!(err, Error::QueryRefused));
    }

    #[test]
    fn response_code_servfail_maps_to_server_failure() {
        let err = Error::from_net(NetError::Dns(DnsError::ResponseCode(ResponseCode::ServFail)));
        assert!(matches!(err, Error::ServerFailure));
    }

    #[test]
    fn no_records_servfail_maps_to_server_failure() {
        let err = Error::from_net(NetError::from(NoRecords::new(
            hickory_resolver::proto::op::Query::default(),
            ResponseCode::ServFail,
        )));
        assert!(matches!(err, Error::ServerFailure));
    }

    #[test]
    fn no_records_refused_maps_to_query_refused() {
        let err = Error::from_net(NetError::from(NoRecords::new(
            hickory_resolver::proto::op::Query::default(),
            ResponseCode::Refused,
        )));
        assert!(matches!(err, Error::QueryRefused));
    }

    #[test]
    fn no_records_nxdomain_maps_to_no_records_found() {
        let err = Error::from_net(NetError::from(NoRecords::new(
            hickory_resolver::proto::op::Query::default(),
            ResponseCode::NXDomain,
        )));
        assert!(matches!(err, Error::NoRecordsFound));
    }

    #[test]
    fn proto_error_maps_to_proto_error() {
        let err = Error::from_net(NetError::Proto(ProtoError::from("some generic error".to_string())));
        assert!(matches!(err, Error::ProtoError { .. }));
    }

    #[test]
    fn other_net_error_maps_to_resolve_error() {
        let err = Error::from_net(NetError::from("some resolve error"));
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
