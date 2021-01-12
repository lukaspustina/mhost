// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::hash::Hash;

use indexmap::set::IndexSet;

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

macro_rules! differ {
    ($mod_name:ident, $rr_type:ty, $($accessor:ident: $field:ident),+) => {
        pub mod $mod_name {
            use super::*;
            #[allow(unused_imports)]
            use crate::resources::rdata::*;
            #[allow(unused_imports)]
            use crate::resources::rdata::parsed_txt::*;

            #[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
            pub enum Field {
                $($field),+
            }

            impl Differ for $rr_type {
                type FieldType = Field;

                fn difference(&self, other: &Self) -> Option<Difference<Self::FieldType>> {
                    let mut diffs = Vec::new();

                    $(
                    if self.$accessor() != other.$accessor() { diffs.push(Field::$field) }
                    )+

                    if diffs.is_empty() {
                        return None;
                    }
                    diffs.sort();

                    Some(Difference { fields: diffs })
                }
            }
        }

    };
}

differ!(mx, MX, preference: Preference, exchange: Exchange);

differ!(
    soa,
    SOA,
    mname: MName,
    rname: RName,
    serial: Serial,
    refresh: Refresh,
    retry: Retry,
    expire: Expire,
    minimum: Minimum
);

differ!(srv, SRV, priority: Priority, weight: Weight, port: Port, target: Target);

differ!(txt, TXT, txt_data: TxtData);

differ!(spf, Spf<'_>, version: Version, words: Words);

differ!(unknown, UNKNOWN, code: Code, rdata: RData);

#[cfg(test)]
mod tests {
    use spectral::prelude::*;

    use crate::IntoName;

    use super::*;

    #[test]
    fn soa_set_differences() {
        crate::utils::tests::logging::init();
        let left = crate::resources::rdata::SOA::new(
            "dns01.p04.nsone.net".into_name().unwrap(),
            "hostmaster.nsone.net".into_name().unwrap(),
            1578047705,
            16384,
            16384,
            1209600,
            3600,
        );

        let right1 = crate::resources::rdata::SOA::new(
            "dns02.p05.nsone.net".into_name().unwrap(),
            "hostmaster.nsone.net".into_name().unwrap(),
            1578047705,
            16384,
            16384,
            1209600,
            3599,
        );

        let right2 = crate::resources::rdata::SOA::new(
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
                fields: vec![super::soa::Field::MName, super::soa::Field::Minimum],
            },
            Difference {
                fields: vec![super::soa::Field::Expire, super::soa::Field::Minimum],
            },
        ];

        assert_that(&diffs).is_some().is_equal_to(&expected);
    }

    mod mx {
        use crate::diff::mx;

        use super::*;

        #[test]
        fn equal() {
            crate::utils::tests::logging::init();
            let left = crate::resources::rdata::MX::new(10, "mx.pustina.de".into_name().unwrap());

            let diff = left.difference(&left);

            assert_that(&diff).is_none();
        }

        #[test]
        fn diff_all() {
            crate::utils::tests::logging::init();
            let left = crate::resources::rdata::MX::new(10, "mx.pustina.de".into_name().unwrap());

            let right = crate::resources::rdata::MX::new(20, "mail.pustina.de".into_name().unwrap());

            let diff = left.difference(&right);

            assert_that(&diff)
                .is_some()
                .map(|x| &x.fields)
                .is_equal_to(&vec![mx::Field::Preference, mx::Field::Exchange]);
        }
    }

    mod soa {
        use crate::diff::soa;

        use super::*;

        #[test]
        fn equal() {
            crate::utils::tests::logging::init();
            let left = crate::resources::rdata::SOA::new(
                "dns01.p04.nsone.net".into_name().unwrap(),
                "hostmaster.nsone.net".into_name().unwrap(),
                1578047705,
                16384,
                16384,
                1209600,
                3600,
            );

            let diff = left.difference(&left);

            assert_that(&diff).is_none();
        }

        #[test]
        fn diff_all() {
            crate::utils::tests::logging::init();
            let left = crate::resources::rdata::SOA::new(
                "dns01.p04.nsone.net".into_name().unwrap(),
                "hostmaster.nsone.net".into_name().unwrap(),
                1578047705,
                16384,
                16384,
                1209600,
                3600,
            );

            let right = crate::resources::rdata::SOA::new(
                "dns02.p03.nsone.net".into_name().unwrap(),
                "hostmaster2.nsone.net".into_name().unwrap(),
                1578047704,
                16383,
                16383,
                1209599,
                3599,
            );

            let diff = left.difference(&right);

            assert_that(&diff).is_some().map(|x| &x.fields).is_equal_to(&vec![
                soa::Field::MName,
                soa::Field::RName,
                soa::Field::Serial,
                soa::Field::Refresh,
                soa::Field::Retry,
                soa::Field::Expire,
                soa::Field::Minimum,
            ]);
        }
    }

    mod srv {
        use crate::diff::srv;

        use super::*;

        #[test]
        fn equal() {
            crate::utils::tests::logging::init();
            let left = crate::resources::rdata::SRV::new(10, 10, 50, "service.pustina.de".into_name().unwrap());

            let diff = left.difference(&left);

            assert_that(&diff).is_none();
        }

        #[test]
        fn diff_all() {
            crate::utils::tests::logging::init();
            let left = crate::resources::rdata::SRV::new(10, 10, 50, "service.pustina.de".into_name().unwrap());

            let right = crate::resources::rdata::SRV::new(20, 20, 150, "dienst.pustina.de".into_name().unwrap());

            let diff = left.difference(&right);

            assert_that(&diff).is_some().map(|x| &x.fields).is_equal_to(&vec![
                srv::Field::Priority,
                srv::Field::Weight,
                srv::Field::Port,
                srv::Field::Target,
            ]);
        }
    }

    mod txt {
        use crate::diff::txt;

        use super::*;

        #[test]
        fn equal() {
            crate::utils::tests::logging::init();
            let left = crate::resources::rdata::TXT::new(vec![
                "v=spf1 mx a ip4:195.230.126.196/26 include:spf.crsend.com include:spf.protection.outlook.com ~all"
                    .to_string(),
            ]);

            let diff = left.difference(&left);

            assert_that(&diff).is_none();
        }

        #[test]
        fn diff_code() {
            crate::utils::tests::logging::init();
            let left = crate::resources::rdata::TXT::new(vec![
                "v=spf1 mx a ip4:192.168.126.196/26 include:spf.crsend.com include:spf.protection.outlook.com ~all"
                    .to_string(),
            ]);

            let right = crate::resources::rdata::TXT::new(vec![
                "v=spf1 a mx ip4:192.168.126.196/26 include:spf.crsend.com include:spf.protection.outlook.com include:antispameurope.com ~all"
                    .to_string(),
            ]);

            let diff = left.difference(&right);

            assert_that(&diff)
                .is_some()
                .map(|x| &x.fields)
                .is_equal_to(&vec![txt::Field::TxtData]);
        }
    }

    mod unknown {
        use crate::diff::unknown;

        use super::*;

        #[test]
        fn equal() {
            crate::utils::tests::logging::init();
            let left = crate::resources::rdata::UNKNOWN::new(10, Default::default());

            let diff = left.difference(&left);

            assert_that(&diff).is_none();
        }

        #[test]
        fn diff_code() {
            crate::utils::tests::logging::init();
            let left = crate::resources::rdata::UNKNOWN::new(10, Default::default());

            let right = crate::resources::rdata::UNKNOWN::new(11, Default::default());

            let diff = left.difference(&right);

            assert_that(&diff)
                .is_some()
                .map(|x| &x.fields)
                .is_equal_to(&vec![unknown::Field::Code]);
        }
    }
}
