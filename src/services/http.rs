// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Size-capped reading of HTTP response bodies.

use super::{Error, Result};

/// Reads the body of `res` as text, failing once it exceeds `max` bytes.
///
/// A `Content-Length` above the limit fails before anything is read; a body without one
/// (chunked) is read only up to the limit, so a misbehaving server cannot exhaust memory.
pub(crate) async fn read_text_capped(mut res: reqwest::Response, max: u64) -> Result<String> {
    if let Some(len) = res.content_length() {
        if len > max {
            return Err(too_large(len, max));
        }
    }

    let mut body = Vec::new();
    while let Some(chunk) = res.chunk().await.map_err(|e| Error::HttpClientError {
        why: "reading body failed",
        source: e,
    })? {
        let len = (body.len() + chunk.len()) as u64;
        if len > max {
            return Err(too_large(len, max));
        }
        body.extend_from_slice(&chunk);
    }

    Ok(String::from_utf8_lossy(&body).into_owned())
}

fn too_large(len: u64, max: u64) -> Error {
    Error::HttpClientErrorMessage {
        why: "response too large",
        details: format!("response size of at least {} bytes exceeds limit of {} bytes", len, max),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(body: &str) -> reqwest::Response {
        reqwest::Response::from(http::Response::new(body.to_string()))
    }

    #[tokio::test]
    async fn body_within_limit_is_read() {
        let body = read_text_capped(response("0123456789"), 10).await.unwrap();
        assert_eq!(body, "0123456789");
    }

    #[tokio::test]
    async fn body_over_limit_fails() {
        let err = read_text_capped(response("0123456789"), 9).await.unwrap_err();
        assert!(err.to_string().contains("too large") || format!("{err:?}").contains("too large"));
    }
}
