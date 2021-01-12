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
use trust_dns_resolver::Name;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Serialize)]
pub struct MX {
    preference: u16,
    exchange: Name,
}

impl MX {
    pub fn new(preference: u16, exchange: Name) -> MX {
        MX { preference, exchange }
    }

    pub fn preference(&self) -> u16 {
        self.preference
    }

    pub fn exchange(&self) -> &Name {
        &self.exchange
    }
}

#[doc(hidden)]
impl From<trust_dns_resolver::proto::rr::rdata::MX> for MX {
    fn from(mx: trust_dns_resolver::proto::rr::rdata::MX) -> Self {
        MX::new(mx.preference(), mx.exchange().clone())
    }
}
