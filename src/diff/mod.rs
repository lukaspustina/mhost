use indexmap::set::IndexSet;
use std::hash::Hash;

pub mod soa;

pub trait Differ {
    type FieldType: Eq;

    fn difference(&self, other: &Self) -> Option<Difference<Self::FieldType>>;
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Difference<T: Eq> {
    pub fields: Vec<T>,
}

impl<T: Eq> Difference<T> {
    pub fn new(fields: Vec<T>) -> Self {
        Difference { fields }
    }

    pub fn has_differences(&self) -> bool {
        self.fields.is_empty()
    }

    pub fn differences(&self) -> &[T] {
        self.fields.as_slice()
    }
}

pub trait SetDiffer<S, T>
where
    S: Eq + Ord,
    T: Differ<FieldType = S> + Eq + Ord + Hash,
{
    fn differences(&self) -> Option<Vec<Difference<S>>>;
}

impl<S, T> SetDiffer<S, T> for IndexSet<T>
where
    S: Eq + Ord,
    T: Differ<FieldType = S> + Eq + Ord + Hash,
{
    fn differences(&self) -> Option<Vec<Difference<S>>> {
        if self.len() < 2 {
            return None;
        }

        let mut diffs = Vec::new();
        let mut iter = self.iter();
        let first = iter.next().unwrap(); // Safe, because len > 1
        for item in iter {
            let diff = first.difference(item);
            if let Some(diff) = diff {
                diffs.push(diff)
            }
        }
        diffs.sort();

        Some(diffs)
    }
}

#[cfg(test)]
mod tests {
    use spectral::prelude::*;

    use super::*;
    use crate::diff::soa::Field;
    use crate::resources::rdata::SOA;
    use crate::IntoName;

    #[test]
    fn soa_all() {
        let left = SOA::new(
            "dns01.p04.nsone.net".into_name().unwrap(),
            "hostmaster.nsone.net".into_name().unwrap(),
            1578047705,
            16384,
            16384,
            1209600,
            3600,
        );

        let right1 = SOA::new(
            "dns02.p05.nsone.net".into_name().unwrap(),
            "hostmaster.nsone.net".into_name().unwrap(),
            1578047705,
            16384,
            16384,
            1209600,
            3599,
        );

        let right2 = SOA::new(
            "dns01.p04.nsone.net".into_name().unwrap(),
            "hostmaster.nsone.net".into_name().unwrap(),
            1578047705,
            16384,
            16384,
            1209599,
            3599,
        );

        let soas: IndexSet<_> = vec![left, right1, right2].into_iter().collect();
        let diffs = soas.differences();

        let expected = vec![
            Difference {
                fields: vec![Field::MName, Field::Minimum],
            },
            Difference {
                fields: vec![Field::Expire, Field::Minimum],
            },
        ];

        assert_that(&diffs).is_some().is_equal_to(&expected);
    }
}
