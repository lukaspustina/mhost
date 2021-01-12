// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt::Debug;
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
    #[error("external service failed")]
    ServiceError {
        #[from]
        source: crate::services::Error,
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

/// This trait enables collections of results or responses to filter just for their errors.
pub trait Errors {
    fn errors(&self) -> Box<dyn Iterator<Item = Box<&dyn std::error::Error>> + '_>;
}
