// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt;
use std::marker::PhantomData;

use super::*;
use crate::services::server_lists::DownloadResponses;

#[derive(Debug)]
pub struct DownloadResponsesStats<'a> {
    pub nameserver_configs: usize,
    pub errors: usize,
    // This is used to please the borrow checker as we currently don't use a borrowed value with lifetime 'a
    phantom: PhantomData<&'a usize>,
}

impl<'a> fmt::Display for DownloadResponsesStats<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fn fmt_errors(errors: usize) -> String {
            if errors == 0 {
                "0 Err".to_string()
            } else {
                format!("{} Err", styles::ERR.paint(errors))
            }
        }

        let str = format!(
            "{num_servers} name servers, {errs}",
            num_servers = styles::BOLD.paint(self.nameserver_configs),
            errs = fmt_errors(self.errors),
        );
        f.write_str(&str)
    }
}

impl<'a> Statistics<'a> for DownloadResponses {
    type StatsOut = DownloadResponsesStats<'a>;

    fn statistics(&'a self) -> Self::StatsOut {
        DownloadResponsesStats {
            nameserver_configs: self.nameserver_configs().count(),
            errors: self.err().count(),
            phantom: PhantomData,
        }
    }
}
