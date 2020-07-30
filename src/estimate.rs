use crate::resolver::{MultiQuery, Resolver, ResolverGroup};
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
        let max_lookups = query.names.len() * query.record_types.len() * self.opts.attempts;

        Estimation {
            min_requests: min_lookups,
            max_requests: max_lookups,
        }
    }
}

impl Estimate for ResolverGroup {
    fn estimate(&self, query: &MultiQuery) -> Estimation {
        self.resolvers
            .iter()
            .map(|x| x.estimate(query))
            .fold(Default::default(), |acc, e| acc + e)
    }
}