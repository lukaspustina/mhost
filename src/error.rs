use thiserror::Error;

#[derive(Debug, Error)]
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
}
