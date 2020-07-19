use crate::resources::rdata::NULL;
use serde::Serialize;

#[derive(Default, Debug, PartialEq, Eq, Hash, Clone, Serialize)]
pub struct UNKNOWN {
    code: u16,
    rdata: NULL,
}

#[allow(dead_code)]
impl UNKNOWN {
    fn code(&self) -> u16 {
        self.code
    }

    fn rdata(&self) -> &NULL {
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
