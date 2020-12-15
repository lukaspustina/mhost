use serde::Serialize;
use trust_dns_resolver::IntoName;
use trust_dns_resolver::Name;

use crate::resolver::{Error, ResolverResult};
use crate::RecordType;

/// UniQuery
///
/// Name's labels are all Rc, so clone is cheap
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
pub struct UniQuery {
    pub(crate) name: Name,
    pub(crate) record_type: RecordType,
}

impl UniQuery {
    pub fn new<N: IntoName>(name: N, record_type: RecordType) -> ResolverResult<UniQuery> {
        let name = name.into_name().map_err(Error::from)?;

        Ok(UniQuery { name, record_type })
    }

    pub fn name(&self) -> &Name {
        &self.name
    }

    pub fn record_type(&self) -> RecordType {
        self.record_type
    }
}

impl From<UniQuery> for MultiQuery {
    fn from(query: UniQuery) -> MultiQuery {
        MultiQuery {
            names: vec![query.name],
            record_types: vec![query.record_type],
        }
    }
}

/// MultiQuery allows to lookup multiple names for multiple record types
///
/// It can be easily constructed from a simple `UniQuery`
///
/// # Example
/// ```
/// # use mhost::resolver::{UniQuery, MultiQuery};
/// # use mhost::RecordType;
/// let query = UniQuery::new("www.example.com", RecordType::A).unwrap();
/// let multi_query: MultiQuery = query.into();
/// ```
#[derive(Debug, Clone)]
pub struct MultiQuery {
    pub(crate) names: Vec<Name>,
    pub(crate) record_types: Vec<RecordType>,
}

impl MultiQuery {
    pub fn new<N: IntoName, S: IntoIterator<Item = N>, T: IntoIterator<Item = RecordType>>(
        names: S,
        record_types: T,
    ) -> ResolverResult<MultiQuery> {
        let names: Vec<_> = names
            .into_iter()
            .map(|name| name.into_name().map_err(Error::from))
            .collect();
        let names: ResolverResult<Vec<_>> = names.into_iter().collect();
        let names = names?;
        let record_types = record_types.into_iter().collect();

        Ok(MultiQuery { names, record_types })
    }

    pub fn single<N: IntoName>(name: N, record_type: RecordType) -> ResolverResult<MultiQuery> {
        MultiQuery::new(vec![name], vec![record_type])
    }

    pub fn multi_name<N: IntoName, S: IntoIterator<Item = N>>(
        names: S,
        record_type: RecordType,
    ) -> ResolverResult<MultiQuery> {
        MultiQuery::new(names, vec![record_type])
    }

    pub fn multi_record<N: IntoName, T: IntoIterator<Item = RecordType>>(
        name: N,
        record_types: T,
    ) -> ResolverResult<MultiQuery> {
        MultiQuery::new(vec![name], record_types)
    }

    pub fn into_uni_queries(self) -> Vec<UniQuery> {
        let mut queries = Vec::new();
        for name in self.names.iter() {
            for record_type in self.record_types.iter() {
                queries.push(UniQuery {
                    name: name.clone(),
                    record_type: *record_type,
                });
            }
        }

        queries
    }

    pub fn num_names(&self) -> usize {
        self.names.len()
    }

    pub fn num_record_types(&self) -> usize {
        self.record_types.len()
    }
}
