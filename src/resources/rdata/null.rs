use serde::Serialize;

#[derive(Default, Debug, PartialEq, Eq, Hash, Clone, Serialize)]
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
