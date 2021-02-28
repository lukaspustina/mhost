// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Statistics module to compute statistical information on query results.

pub mod lookups;
pub mod server_lists;
pub mod whois;

mod styles {
    use lazy_static::lazy_static;
    use yansi::{Color, Style};

    lazy_static! {
        pub static ref NORMAL: Style = Style::default();
        pub static ref BOLD: Style = Style::new(Color::White).bold();
        pub static ref GOOD: Style = Style::new(Color::Green);
        pub static ref WARN: Style = Style::new(Color::Yellow);
        pub static ref ERR: Style = Style::new(Color::Red);
    }
}

pub trait Statistics<'a> {
    type StatsOut;

    fn statistics(&'a self) -> Self::StatsOut;
}

#[derive(Debug)]
pub struct Summary<T: Ord + Clone> {
    pub min: Option<T>,
    pub max: Option<T>,
}

impl<T: Ord + Clone> Summary<T> {
    pub fn summary(values: &[T]) -> Summary<T> {
        let min = values.iter().min().cloned();
        let max = values.iter().max().cloned();

        Summary { min, max }
    }
}
