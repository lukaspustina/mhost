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
