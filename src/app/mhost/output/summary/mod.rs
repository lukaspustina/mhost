// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use super::*;

pub mod diff;
pub mod lookups;
pub mod propagation;
pub mod verify;
pub mod whois;

// SummaryOptions and Rendering are now in crate::app::common::rendering.
// Re-exported here for backward compatibility.
pub use crate::app::common::rendering::{Rendering, SummaryOptions};

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
