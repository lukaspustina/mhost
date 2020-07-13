use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum Error {
    #[error("DNS resolver error")]
    DnsResolverError {
        #[from]
        source: trust_dns_resolver::error::ResolveError,
    },
    #[error("DNS protocol error")]
    DnsProtocolError {
        #[from]
        source: trust_dns_resolver::proto::error::ProtoError,
    },
    #[error("failed to parse '{what}' to {to}")]
    ParserError { what: String, to: &'static str },
}
