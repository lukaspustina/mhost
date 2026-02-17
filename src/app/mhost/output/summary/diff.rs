// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use yansi::Paint;

use super::*;
use crate::app::modules::diff::diff::DiffResults;
use crate::app::output::styles as output_styles;

impl SummaryFormatter for DiffResults {
    fn output<W: Write>(&self, writer: &mut W, opts: &SummaryOptions) -> Result<()> {
        writeln!(writer, "DNS Diff for {}", self.domain_name)?;
        writeln!(writer, "  Left:  {}", self.left_servers.join(", "))?;
        writeln!(writer, "  Right: {}", self.right_servers.join(", "))?;
        writeln!(writer)?;

        if self.record_diffs.is_empty() {
            writeln!(writer, " {} No differences found.", output_styles::ok_prefix())?;
            return Ok(());
        }

        for diff in &self.record_diffs {
            writeln!(writer, " {} {}:", output_styles::caption_prefix(), diff.record_type)?;

            for record in &diff.only_left {
                writeln!(
                    writer,
                    "   {} left only: {}",
                    "-".paint(output_styles::ATTENTION),
                    record.render(opts),
                )?;
            }

            for record in &diff.only_right {
                writeln!(
                    writer,
                    "   {} right only: {}",
                    "+".paint(output_styles::OK),
                    record.render(opts),
                )?;
            }
        }

        Ok(())
    }
}
