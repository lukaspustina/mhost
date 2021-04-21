// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Derived from trust-dns by Benjamin Fry <benjaminfry@me.com>
// cf. https://github.com/bluejekyll/trust-dns
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use serde::Serialize;

#[derive(Default, Debug, PartialEq, Eq, Hash, Clone, Serialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct NULL {
    anything: Option<Vec<u8>>,
}

impl NULL {
    /// Construct a new NULL RData
    pub fn new() -> NULL {
        Default::default()
    }

    /// Constructs a new NULL RData with the associated data
    pub fn with(anything: Vec<u8>) -> NULL {
        NULL {
            anything: Some(anything),
        }
    }

    /// Returns the buffer stored in the NULL
    pub fn anything(&self) -> Option<&[u8]> {
        self.anything.as_ref().map(|bytes| &bytes[..])
    }
}

#[doc(hidden)]
impl From<trust_dns_resolver::proto::rr::rdata::NULL> for NULL {
    fn from(null: trust_dns_resolver::proto::rr::rdata::NULL) -> Self {
        NULL {
            anything: null.anything().map(|x| x.to_vec()),
        }
    }
}
