// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Derived from trust-dns by Benjamin Fry <benjaminfry@me.com>
// cf. https://github.com/bluejekyll/trust-dns
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms..

use serde::Serialize;
use trust_dns_resolver::Name;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct SRV {
    priority: u16,
    weight: u16,
    port: u16,
    target: Name,
}

impl SRV {
    pub fn new(priority: u16, weight: u16, port: u16, target: Name) -> SRV {
        SRV {
            priority,
            weight,
            port,
            target,
        }
    }

    pub fn priority(&self) -> u16 {
        self.priority
    }

    pub fn weight(&self) -> u16 {
        self.weight
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn target(&self) -> &Name {
        &self.target
    }
}

#[doc(hidden)]
impl From<trust_dns_resolver::proto::rr::rdata::SRV> for SRV {
    fn from(srv: trust_dns_resolver::proto::rr::rdata::SRV) -> Self {
        SRV {
            priority: srv.priority(),
            weight: srv.weight(),
            port: srv.port(),
            target: srv.target().clone(),
        }
    }
}
