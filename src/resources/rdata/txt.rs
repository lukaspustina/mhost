// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Derived from trust-dns by Benjamin Fry <benjaminfry@me.com>
// cf. https://github.com/bluejekyll/trust-dns
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::slice::Iter;

use serde::Serialize;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct TXT {
    txt_data: Box<[Box<[u8]>]>,
}

impl TXT {
    pub fn new(txt_data: Vec<String>) -> TXT {
        TXT {
            txt_data: txt_data
                .into_iter()
                .map(|s| s.as_bytes().to_vec().into_boxed_slice())
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }

    pub fn txt_data(&self) -> &[Box<[u8]>] {
        &self.txt_data
    }

    pub fn iter(&self) -> Iter<Box<[u8]>> {
        self.txt_data.iter()
    }

    pub fn is_spf(&self) -> bool {
        if let Some(first) = self.iter().next() {
            let str = String::from_utf8_lossy(first);
            str.starts_with("v=spf")
        } else {
            false
        }
    }

    pub fn as_string(&self) -> String {
        self.iter()
            .map(|x| String::from_utf8_lossy(x))
            .collect::<Vec<_>>()
            .join("")
    }
}

#[doc(hidden)]
impl From<trust_dns_resolver::proto::rr::rdata::TXT> for TXT {
    #[allow(clippy::map_clone)]
    fn from(txt: trust_dns_resolver::proto::rr::rdata::TXT) -> Self {
        let txt_data = txt.iter().map(|s| s.clone()).collect::<Vec<_>>().into_boxed_slice();
        TXT { txt_data }
    }
}

#[cfg(test)]
mod tests {
    use spectral::prelude::*;

    use super::*;

    #[test]
    fn is_spf() {
        crate::utils::tests::logging::init();
        let record = "v=spf1 ip4:192.168.0.0/24 +ip6:fc00::/7 ?a a/24 a:offsite.example.com/24 ~mx mx/24 mx:mx.example.com/24 -ptr +ptr:mx.example.com exists:%{ir}.%{l1r+-}._spf.%{d} ?include:_spf.example.com redirect=_spf.example.com exp=explain._spf.%{d} -all";

        let txt = TXT::new(vec![record.to_string()]);

        asserting("txt record is SPF record").that(&txt.is_spf()).is_true();
    }

    #[test]
    fn is_not_spf() {
        crate::utils::tests::logging::init();
        let record = "3897592857random_stuff09389025";

        let txt = TXT::new(vec![record.to_string()]);

        asserting("txt record is SPF record").that(&txt.is_spf()).is_false();
    }
}
