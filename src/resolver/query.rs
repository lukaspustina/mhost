// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Query types for DNS lookups.
//!
//! [`UniQuery`] represents a single (name, record type) pair. [`MultiQuery`] represents
//! the Cartesian product of multiple names and record types, enabling batch lookups in
//! a single call.

use hickory_resolver::IntoName;
use hickory_resolver::Name;
use serde::{Deserialize, Serialize};

use crate::resolver::{Error, ResolverResult};
use crate::RecordType;

/// A single DNS query: one name and one record type.
///
/// Cloning is cheap because `Name` labels are reference-counted.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize)]
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

/// A batch DNS query: the Cartesian product of multiple names and record types.
///
/// A `MultiQuery` can be constructed from individual components or converted from a [`UniQuery`].
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

    /// Lookup a single name for a single records type
    pub fn single<N: IntoName>(name: N, record_type: RecordType) -> ResolverResult<MultiQuery> {
        MultiQuery::new(vec![name], vec![record_type])
    }

    /// Lookup a multiple names for a single records type
    pub fn multi_name<N: IntoName, S: IntoIterator<Item = N>>(
        names: S,
        record_type: RecordType,
    ) -> ResolverResult<MultiQuery> {
        MultiQuery::new(names, vec![record_type])
    }

    /// Lookup a single name for a multiple records types
    pub fn multi_record<N: IntoName, T: IntoIterator<Item = RecordType>>(
        name: N,
        record_types: T,
    ) -> ResolverResult<MultiQuery> {
        MultiQuery::new(vec![name], record_types)
    }

    /// Converts this `MultiQuery` into individual `UniQuery`s
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

    /// Returns number of names of this `MultiQuery`
    pub fn num_names(&self) -> usize {
        self.names.len()
    }

    /// Returns number of record types of this `MultiQuery`
    pub fn num_record_types(&self) -> usize {
        self.record_types.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RecordType;

    #[test]
    fn uni_query_new_and_accessors() {
        let q = UniQuery::new("example.com.", RecordType::A).unwrap();
        assert_eq!(q.name().to_utf8(), "example.com.");
        assert_eq!(q.record_type(), RecordType::A);
    }

    #[test]
    fn uni_query_invalid_name() {
        // A label exceeding 63 characters is not a valid DNS name
        let long_label = "a".repeat(64);
        let result = UniQuery::new(long_label.as_str(), RecordType::A);
        assert!(result.is_err());
    }

    #[test]
    fn multi_query_single() {
        let mq = MultiQuery::single("example.com.", RecordType::AAAA).unwrap();
        assert_eq!(mq.num_names(), 1);
        assert_eq!(mq.num_record_types(), 1);

        let queries = mq.into_uni_queries();
        assert_eq!(queries.len(), 1);
        assert_eq!(queries[0].name().to_utf8(), "example.com.");
        assert_eq!(queries[0].record_type(), RecordType::AAAA);
    }

    #[test]
    fn multi_query_multi_name() {
        let mq = MultiQuery::multi_name(vec!["a.example.com.", "b.example.com."], RecordType::A).unwrap();
        assert_eq!(mq.num_names(), 2);
        assert_eq!(mq.num_record_types(), 1);

        let queries = mq.into_uni_queries();
        assert_eq!(queries.len(), 2);
        assert_eq!(queries[0].name().to_utf8(), "a.example.com.");
        assert_eq!(queries[1].name().to_utf8(), "b.example.com.");
    }

    #[test]
    fn multi_query_multi_record() {
        let mq =
            MultiQuery::multi_record("example.com.", vec![RecordType::A, RecordType::MX, RecordType::TXT]).unwrap();
        assert_eq!(mq.num_names(), 1);
        assert_eq!(mq.num_record_types(), 3);

        let queries = mq.into_uni_queries();
        assert_eq!(queries.len(), 3);
        assert_eq!(queries[0].record_type(), RecordType::A);
        assert_eq!(queries[1].record_type(), RecordType::MX);
        assert_eq!(queries[2].record_type(), RecordType::TXT);
    }

    #[test]
    fn multi_query_cartesian_product() {
        let mq = MultiQuery::new(
            vec!["a.example.com.", "b.example.com."],
            vec![RecordType::A, RecordType::MX, RecordType::TXT],
        )
        .unwrap();

        let queries = mq.into_uni_queries();
        assert_eq!(queries.len(), 6);

        // Names are outer loop, types are inner loop
        assert_eq!(queries[0].name().to_utf8(), "a.example.com.");
        assert_eq!(queries[0].record_type(), RecordType::A);
        assert_eq!(queries[1].name().to_utf8(), "a.example.com.");
        assert_eq!(queries[1].record_type(), RecordType::MX);
        assert_eq!(queries[2].name().to_utf8(), "a.example.com.");
        assert_eq!(queries[2].record_type(), RecordType::TXT);
        assert_eq!(queries[3].name().to_utf8(), "b.example.com.");
        assert_eq!(queries[3].record_type(), RecordType::A);
        assert_eq!(queries[4].name().to_utf8(), "b.example.com.");
        assert_eq!(queries[4].record_type(), RecordType::MX);
        assert_eq!(queries[5].name().to_utf8(), "b.example.com.");
        assert_eq!(queries[5].record_type(), RecordType::TXT);
    }

    #[test]
    fn multi_query_from_uni_query() {
        let uq = UniQuery::new("example.com.", RecordType::MX).unwrap();
        let mq: MultiQuery = uq.into();

        assert_eq!(mq.num_names(), 1);
        assert_eq!(mq.num_record_types(), 1);

        let queries = mq.into_uni_queries();
        assert_eq!(queries.len(), 1);
        assert_eq!(queries[0].name().to_utf8(), "example.com.");
        assert_eq!(queries[0].record_type(), RecordType::MX);
    }
}
