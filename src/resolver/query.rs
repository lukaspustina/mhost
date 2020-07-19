use serde::Serialize;
use trust_dns_resolver::IntoName;
use trust_dns_resolver::Name;

use crate::error::Error;
use crate::{RecordType, Result};

/// UniQuery
///
/// Name's labels are all Rc, so clone is cheap
#[derive(Debug, Clone, Serialize)]
pub struct UniQuery {
    pub(crate) name: Name,
    pub(crate) record_type: RecordType,
}

impl UniQuery {
    pub fn new<N: IntoName>(name: N, record_type: RecordType) -> Result<UniQuery> {
        let name = name.into_name().map_err(Error::from)?;

        Ok(UniQuery { name, record_type })
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
    pub fn new<N: IntoName, S: Into<Vec<N>>, T: Into<Vec<RecordType>>>(
        names: S,
        record_types: T,
    ) -> Result<MultiQuery> {
        let names: Vec<_> = names
            .into()
            .into_iter()
            .map(|name| name.into_name().map_err(Error::from))
            .collect();
        let names: Result<Vec<_>> = names.into_iter().collect();
        let names = names?;
        let record_types = record_types.into();

        Ok(MultiQuery { names, record_types })
    }

    pub fn multi_name<N: IntoName, S: Into<Vec<N>>>(names: S, record_type: RecordType) -> Result<MultiQuery> {
        MultiQuery::new(names, [record_type])
    }

    pub fn multi_record<N: IntoName, T: Into<Vec<RecordType>>>(name: N, record_types: T) -> Result<MultiQuery> {
        MultiQuery::new([name], record_types)
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
}
