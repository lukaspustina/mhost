use crate::error::Error;
use crate::resolver::Resolver;
use crate::{MultiQuery, Query};
use futures::stream::{self, StreamExt};
use log::{debug, trace};
use trust_dns_resolver::error::{ResolveError, ResolveErrorKind};
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::proto::xfer::DnsRequestOptions;
use trust_dns_resolver::Name;

#[derive(Debug)]
pub enum Lookup {
    Lookup(trust_dns_resolver::lookup::Lookup),
    NxDomain,
    Timeout,
    Error(Error),
}

impl From<std::result::Result<trust_dns_resolver::lookup::Lookup, ResolveError>> for Lookup {
    fn from(res: std::result::Result<trust_dns_resolver::lookup::Lookup, ResolveError>) -> Self {
        match res {
            Ok(lookup) => Lookup::Lookup(lookup),
            Err(err) => match err.kind() {
                ResolveErrorKind::NoRecordsFound { .. } => Lookup::NxDomain,
                ResolveErrorKind::Timeout => Lookup::Timeout,
                _ => Lookup::Error(Error::from(err)),
            },
        }
    }
}

impl Lookup {
    pub(crate) async fn lookup(resolver: Resolver, q: Query) -> Lookup {
        do_lookup(&resolver, q.name, q.record_type).await
    }

    pub(crate) async fn multi_lookups(resolver: Resolver, mq: MultiQuery) -> Vec<Lookup> {
        let MultiQuery { name, record_types } = mq;
        let lookups: Vec<_> = record_types
            .into_iter()
            .map(|record_type| do_lookup(&resolver, name.clone(), record_type))
            .collect();

        stream::iter(lookups)
            .buffer_unordered(resolver.opts.max_concurrent)
            .inspect(|lookup| trace!("Received lookup {:?}", lookup))
            .collect::<Vec<Lookup>>()
            .await
    }
}

async fn do_lookup(resolver: &Resolver, name: Name, record_type: RecordType) -> Lookup {
    let lookup = resolver
        .inner
        .lookup(name, record_type, DnsRequestOptions::default())
        .await
        .into();
    debug!(
        "Received Lookup for record type {} at {:?}.",
        record_type, resolver.name
    );

    lookup
}
