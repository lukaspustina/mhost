use crate::error::Error;
use crate::Result;

use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::IntoName;
use trust_dns_resolver::Name;

#[derive(Debug, Clone)]
pub struct Query {
    pub(crate) name: Name,
    pub(crate) record_type: RecordType,
}

impl Query {
    pub fn new<N: IntoName>(name: N, record_type: RecordType) -> Result<Query> {
        let name = name.into_name().map_err(Error::from)?;

        Ok(Query { name, record_type })
    }
}

impl From<Query> for MultiQuery {
    fn from(query: Query) -> MultiQuery {
        MultiQuery {
            name: query.name,
            record_types: vec![query.record_type],
        }
    }
}

/// MultiQuery allows to specify multiple record lookups an once.
///
/// It can be easily constructed from a simple `Query`
///
/// # Example
/// ```
/// # use mhost::{Query, MultiQuery};
/// # use mhost::RecordType;
/// let query = Query::new("www.example.com", RecordType::A).unwrap();
/// let multi_query: MultiQuery = query.into();
/// ```
#[derive(Debug, Clone)]
pub struct MultiQuery {
    pub(crate) name: Name,
    pub(crate) record_types: Vec<RecordType>,
}

impl MultiQuery {
    pub fn new<N: IntoName, T: Into<Vec<RecordType>>>(name: N, record_types: T) -> Result<MultiQuery> {
        let name = name.into_name().map_err(Error::from)?;
        let record_types = record_types.into();

        Ok(MultiQuery { name, record_types })
    }
}
