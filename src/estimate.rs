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
                .take(self.opts.limit.unwrap_or_else(|| self.resolvers.len()))
                .map(|x| x.estimate(query))
                .fold(Default::default(), |acc, e| acc + e),
            // This is technically not correct, since each resolver could have different options, but due to the way,
            // ResolverGroup is constructed, this is fine.
            Mode::Uni => self.resolvers.get(0).map(|x| x.estimate(query)).unwrap_or_default(),
        }
    }
}
