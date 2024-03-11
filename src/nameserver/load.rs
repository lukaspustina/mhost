// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::nameserver::{NameServerConfig, NameServerConfigGroup};
use crate::resolver::ResolverGroup;
use crate::{Error, Result};
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncBufReadExt;
use tokio::io::BufReader;

impl NameServerConfigGroup {
    pub async fn from_file<P: AsRef<Path>>(resolvers: &ResolverGroup, path: P) -> Result<NameServerConfigGroup> {
        NameServerConfigGroup::do_from_file(resolvers, path, true).await
    }

    pub async fn from_file_abort_on_error<P: AsRef<Path>>(
        resolvers: &ResolverGroup,
        path: P,
        abort_on_error: bool,
    ) -> Result<NameServerConfigGroup> {
        NameServerConfigGroup::do_from_file(resolvers, path, abort_on_error).await
    }

    async fn do_from_file<P: AsRef<Path>>(
        resolvers: &ResolverGroup,
        path: P,
        abort_on_error: bool,
    ) -> Result<NameServerConfigGroup> {
        let file = File::open(path).await?;
        let mut buf_reader = BufReader::new(file);

        let mut configs = Vec::new();
        let mut buffer = String::new();
        loop {
            buffer.clear();
            let len = buf_reader.read_line(&mut buffer).await?;
            if len == 0 {
                break;
            }
            if buffer.starts_with("//") {
                continue;
            }
            let config = NameServerConfig::from_str_with_resolution(resolvers, &buffer)
                .await
                .map_err(|e| Error::ParserError {
                    what: buffer.clone(),
                    to: "NameServerConfig",
                    why: e.to_string(),
                });

            match config {
                Ok(config) => configs.push(config),
                Err(e) if abort_on_error => return Err(e),
                _ => break,
            }
        }

        Ok(NameServerConfigGroup::new(configs))
    }
}
