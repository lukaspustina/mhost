// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashSet;

use crate::Error;

use super::*;

pub mod lookups;
pub mod whois;

#[derive(Debug)]
pub struct SummaryOptions {
    /// Show numbers, times, and dates in human readable form
    human: bool,
    /// Reduce output to an as concise as possible form
    condensed: bool,
    /// Show domain names queried
    show_domain_names: bool,
}

impl SummaryOptions {
    pub fn new(human: bool, condensed: bool, show_domain_names: bool) -> SummaryOptions {
        SummaryOptions {
            human,
            condensed,
            show_domain_names,
        }
    }

    pub fn human(&self) -> bool {
        self.human
    }

    pub fn condensed(&self) -> bool {
        self.condensed
    }

    pub fn show_domain_names(&self) -> bool {
        self.show_domain_names
    }
}

impl Default for SummaryOptions {
    fn default() -> Self {
        SummaryOptions {
            human: true,
            condensed: false,
            show_domain_names: false,
        }
    }
}

impl<'a> TryFrom<Vec<&'a str>> for SummaryOptions {
    type Error = Error;

    fn try_from(values: Vec<&'a str>) -> std::result::Result<Self, Self::Error> {
        let options: HashSet<&str> = values.into_iter().collect();
        Ok(SummaryOptions {
            human: options.contains("human"),
            condensed: options.contains("condensed"),
            show_domain_names: options.contains("show-domain-names"),
        })
    }
}

#[derive(Debug, Default)]
pub struct SummaryFormat {
    opts: SummaryOptions,
}

impl SummaryFormat {
    pub fn new(opts: SummaryOptions) -> SummaryFormat {
        SummaryFormat { opts }
    }

    pub fn opts(&self) -> &SummaryOptions {
        &self.opts
    }
}

pub trait SummaryFormatter {
    fn output<W: Write>(&self, writer: &mut W, opts: &SummaryOptions) -> Result<()>;
}

impl<T: SummaryFormatter> OutputFormat<T> for SummaryFormat {
    fn output<W: Write>(&self, writer: &mut W, data: &T) -> Result<()> {
        data.output(writer, &self.opts)
    }
}

trait Rendering {
    fn render(&self, opts: &SummaryOptions) -> String;

    #[allow(unused_variables)]
    fn render_with_suffix(&self, suffix: &str, opts: &SummaryOptions) -> String {
        self.render(opts)
    }
}
