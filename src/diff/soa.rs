use crate::diff::{Difference, Differ};
use crate::resources::rdata::SOA;

#[derive(Debug, PartialEq, Eq)]
pub enum Field {
    MName,
    RName,
    Serial,
    Refresh,
    Retry,
    Expire,
    Minimum,
}

impl Differ for SOA {
    type FieldType = Field;

    fn difference(&self, other: &Self) -> Difference<Self::FieldType> {
        let mut diffs = Vec::new();

        if self.mname() != other.mname() {
            diffs.push(Field::MName)
        }
        if self.rname() != other.rname() {
            diffs.push(Field::RName)
        }
        if self.serial() != other.serial() {
            diffs.push(Field::Serial)
        }
        if self.refresh() != other.refresh() {
            diffs.push(Field::Refresh)
        }
        if self.retry() != other.retry() {
            diffs.push(Field::Retry)
        }
        if self.expire() != other.expire() {
            diffs.push(Field::Expire)
        }
        if self.minimum() != other.minimum() {
            diffs.push(Field::Minimum)
        }

        Difference { fields: diffs }
    }
}

#[cfg(test)]
mod tests {
    use spectral::prelude::*;

    use crate::IntoName;

    use super::*;

    #[test]
    fn soa_equal() {
        let left = SOA::new(
            "dns01.p04.nsone.net".into_name().unwrap(),
            "hostmaster.nsone.net".into_name().unwrap(),
            1578047705,
            16384,
            16384,
            1209600,
            3600,
        );

        let diff = left.difference(&left);

        assert_that(&diff).map(|x| &x.fields).is_empty();
    }

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

        let right = SOA::new(
            "dns02.p03.nsone.net".into_name().unwrap(),
            "hostmaster2.nsone.net".into_name().unwrap(),
            1578047704,
            16383,
            16383,
            1209599,
            3599,
        );

        let diff = left.difference(&right);

        assert_that(&diff).map(|x| &x.fields).is_equal_to(&vec![
            Field::MName,
            Field::RName,
            Field::Serial,
            Field::Refresh,
            Field::Retry,
            Field::Expire,
            Field::Minimum,
        ]);
    }
}
