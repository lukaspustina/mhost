// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Compute run time estimates for various queries.

use crate::resolver::{Mode, MultiQuery, Resolver, ResolverGroup};
use std::fmt;
use std::ops::Add;

pub trait Estimate {
    fn estimate(&self, query: &MultiQuery) -> Estimation;
}

#[derive(Debug, Default)]
pub struct Estimation {
    pub min_requests: usize,
    pub max_requests: usize,
}

impl Add for Estimation {
    type Output = Estimation;

    fn add(self, rhs: Self) -> Self::Output {
        Estimation {
            min_requests: self.min_requests + rhs.min_requests,
            max_requests: self.max_requests + rhs.max_requests,
        }
    }
}

impl fmt::Display for Estimation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str = format!("[min={}, max={}]", self.min_requests, self.max_requests);
        f.write_str(&str)
    }
}

impl Estimate for Resolver {
    fn estimate(&self, query: &MultiQuery) -> Estimation {
        let min_lookups = query.names.len() * query.record_types.len();
        let max_lookups = query.names.len() * query.record_types.len() * (1 + self.opts.retries);

        Estimation {
            min_requests: min_lookups,
            max_requests: max_lookups,
        }
    }
}

impl Estimate for ResolverGroup {
    fn estimate(&self, query: &MultiQuery) -> Estimation {
        match self.opts.mode {
            Mode::Multi => self
                .resolvers
                .iter()
                .take(self.opts.limit.unwrap_or(self.resolvers.len()))
                .map(|x| x.estimate(query))
                .fold(Default::default(), |acc, e| acc + e),
            // This is technically not correct, since each resolver could have different options, but due to the way,
            // ResolverGroup is constructed, this is fine.
            Mode::Uni => self.resolvers.first().map(|x| x.estimate(query)).unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nameserver::NameServerConfig;
    use crate::resolver::{ResolverGroupOpts, ResolverOpts};
    use crate::RecordType;
    use std::net::Ipv4Addr;

    fn make_resolver(retries: usize) -> Resolver {
        let mut opts = ResolverOpts::default();
        opts.retries = retries;
        let ns = NameServerConfig::udp((Ipv4Addr::new(127, 0, 0, 1), 53));
        Resolver::new_for_test(opts, ns)
    }

    #[test]
    fn estimation_add() {
        let a = Estimation {
            min_requests: 2,
            max_requests: 4,
        };
        let b = Estimation {
            min_requests: 3,
            max_requests: 6,
        };
        let sum = a + b;
        assert_eq!(sum.min_requests, 5);
        assert_eq!(sum.max_requests, 10);
    }

    #[test]
    fn estimation_display() {
        let e = Estimation {
            min_requests: 3,
            max_requests: 9,
        };
        assert_eq!(format!("{}", e), "[min=3, max=9]");
    }

    #[test]
    fn estimation_default() {
        let e = Estimation::default();
        assert_eq!(e.min_requests, 0);
        assert_eq!(e.max_requests, 0);
    }

    #[test]
    fn resolver_estimate_no_retries() {
        let resolver = make_resolver(0);
        let query = MultiQuery::new(
            vec!["a.example.com.", "b.example.com."],
            vec![RecordType::A, RecordType::MX, RecordType::TXT],
        )
        .unwrap();
        let est = resolver.estimate(&query);

        assert_eq!(est.min_requests, 6);
        assert_eq!(est.max_requests, 6);
    }

    #[test]
    fn resolver_estimate_with_retries() {
        let resolver = make_resolver(2);
        let query = MultiQuery::multi_record("example.com.", vec![RecordType::A, RecordType::MX]).unwrap();
        let est = resolver.estimate(&query);

        assert_eq!(est.min_requests, 2);
        assert_eq!(est.max_requests, 6); // 2 * (1 + 2)
    }

    #[test]
    fn resolver_group_multi_mode() {
        let resolvers = vec![make_resolver(0), make_resolver(0), make_resolver(0)];
        let group = ResolverGroup::new(
            resolvers,
            ResolverGroupOpts {
                mode: Mode::Multi,
                limit: None,
                ..Default::default()
            },
        );
        let query = MultiQuery::single("example.com.", RecordType::A).unwrap();
        let est = group.estimate(&query);

        // 3 resolvers, each estimates min=1, max=1 (0 retries)
        assert_eq!(est.min_requests, 3);
        assert_eq!(est.max_requests, 3);
    }

    #[test]
    fn resolver_group_multi_mode_with_limit() {
        let resolvers = vec![make_resolver(0), make_resolver(0), make_resolver(0)];
        let group = ResolverGroup::new(
            resolvers,
            ResolverGroupOpts {
                mode: Mode::Multi,
                limit: Some(2),
                ..Default::default()
            },
        );
        let query = MultiQuery::single("example.com.", RecordType::A).unwrap();
        let est = group.estimate(&query);

        // Only 2 resolvers counted due to limit
        assert_eq!(est.min_requests, 2);
        assert_eq!(est.max_requests, 2);
    }

    #[test]
    fn resolver_group_uni_mode() {
        let resolvers = vec![make_resolver(1), make_resolver(1)];
        let group = ResolverGroup::new(
            resolvers,
            ResolverGroupOpts {
                mode: Mode::Uni,
                limit: None,
                ..Default::default()
            },
        );
        let query = MultiQuery::single("example.com.", RecordType::A).unwrap();
        let est = group.estimate(&query);

        // Uni mode uses first resolver's estimate only
        assert_eq!(est.min_requests, 1);
        assert_eq!(est.max_requests, 2); // 1 * (1 + 1)
    }
}
