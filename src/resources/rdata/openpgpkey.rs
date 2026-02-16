// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct OPENPGPKEY {
    public_key: Vec<u8>,
}

impl OPENPGPKEY {
    pub fn new(public_key: Vec<u8>) -> OPENPGPKEY {
        OPENPGPKEY { public_key }
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openpgpkey_new_and_accessors() {
        let key_data = vec![0x01, 0x02, 0x03, 0x04];
        let key = OPENPGPKEY::new(key_data.clone());
        assert_eq!(key.public_key(), &key_data[..]);
    }

    #[test]
    fn openpgpkey_empty() {
        let key = OPENPGPKEY::new(vec![]);
        assert!(key.public_key().is_empty());
    }
}

#[doc(hidden)]
impl From<hickory_resolver::proto::rr::rdata::OPENPGPKEY> for OPENPGPKEY {
    fn from(key: hickory_resolver::proto::rr::rdata::OPENPGPKEY) -> Self {
        OPENPGPKEY {
            public_key: key.public_key().to_vec(),
        }
    }
}
