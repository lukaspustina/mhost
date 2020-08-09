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
}

impl Default for SummaryOptions {
    fn default() -> Self {
        SummaryOptions {
            human: true,
            condensed: false,
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
        })
    }
}

#[derive(Debug)]
pub struct SummaryFormat {
    opts: SummaryOptions,
}

impl SummaryFormat {
    pub fn new(opts: SummaryOptions) -> SummaryFormat {
        SummaryFormat { opts }
    }
}

impl Default for SummaryFormat {
    fn default() -> Self {
        SummaryFormat {
            opts: SummaryOptions::default(),
        }
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
