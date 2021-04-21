// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Derived from trust-dns by Benjamin Fry <benjaminfry@me.com>
// cf. https://github.com/bluejekyll/trust-dns
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::resources::rdata::NULL;
use serde::Serialize;

#[derive(Default, Debug, PartialEq, Eq, Hash, Clone, Serialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct UNKNOWN {
    code: u16,
    rdata: NULL,
}

#[allow(dead_code)]
impl UNKNOWN {
    pub fn new(code: u16, rdata: NULL) -> UNKNOWN {
        UNKNOWN { code, rdata }
    }

    pub fn code(&self) -> u16 {
        self.code
    }

    pub fn rdata(&self) -> &NULL {
        &self.rdata
    }
}

#[doc(hidden)]
impl From<(u16, trust_dns_resolver::proto::rr::rdata::NULL)> for UNKNOWN {
    fn from(unknown: (u16, trust_dns_resolver::proto::rr::rdata::NULL)) -> Self {
        UNKNOWN {
            code: unknown.0,
            rdata: unknown.1.into(),
        }
    }
}
