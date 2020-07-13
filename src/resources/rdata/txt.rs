use serde::Serialize;
use std::slice::Iter;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
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
}

#[doc(hidden)]
impl From<trust_dns_resolver::proto::rr::rdata::TXT> for TXT {
    #[allow(clippy::map_clone)]
    fn from(txt: trust_dns_resolver::proto::rr::rdata::TXT) -> Self {
        let txt_data = txt.iter().map(|s| s.clone()).collect::<Vec<_>>().into_boxed_slice();
        TXT { txt_data }
    }
}
