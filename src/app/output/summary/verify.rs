// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use yansi::Paint;

use super::*;
use crate::app::modules::verify::verify::VerifyResults;
use crate::app::output::styles as output_styles;

impl SummaryFormatter for VerifyResults {
    fn output<W: Write>(&self, writer: &mut W, opts: &SummaryOptions) -> Result<()> {
        writeln!(
            writer,
            "DNS Verification for {} (from {})",
            self.origin, self.zone_file
        )?;
        writeln!(writer)?;

        if self.missing.is_empty() && self.extra.is_empty() && self.ttl_drifts.is_empty() {
            writeln!(
                writer,
                " {} All {} records verified.",
                output_styles::ok_prefix().paint(output_styles::OK),
                self.matches.len()
            )?;
            return Ok(());
        }

        let missing_header = "Missing records (in zone file but not in live DNS)";
        if !self.missing.is_empty() {
            writeln!(
                writer,
                " {} {missing_header}:",
                output_styles::error_prefix().paint(output_styles::ERROR),
            )?;
            for record in &self.missing {
                writeln!(
                    writer,
                    "   {} {} {}",
                    "-".paint(output_styles::ERROR),
                    record.name(),
                    record.render(opts),
                )?;
            }
            writeln!(writer)?;
        }

        let extra_header = "Extra records (in live DNS but not in zone file)";
        if !self.extra.is_empty() {
            writeln!(
                writer,
                " {} {extra_header}:",
                output_styles::attention_prefix().paint(output_styles::ATTENTION),
            )?;
            for record in &self.extra {
                writeln!(
                    writer,
                    "   {} {} {}",
                    "+".paint(output_styles::ATTENTION),
                    record.name(),
                    record.render(opts),
                )?;
            }
            writeln!(writer)?;
        }

        let ttl_header = "TTL drifts";
        if !self.ttl_drifts.is_empty() {
            writeln!(
                writer,
                " {} {ttl_header}:",
                output_styles::attention_prefix().paint(output_styles::ATTENTION),
            )?;
            for drift in &self.ttl_drifts {
                writeln!(
                    writer,
                    "   {} {} {} expected TTL {}, actual {}",
                    "~".paint(output_styles::ATTENTION),
                    drift.record.name(),
                    drift.record.render(opts),
                    drift.expected_ttl,
                    drift.actual_ttl,
                )?;
            }
            writeln!(writer)?;
        }

        // Summary line
        writeln!(
            writer,
            " {} matched, {} missing, {} extra{}",
            self.matches.len(),
            self.missing.len(),
            self.extra.len(),
            if self.ttl_drifts.is_empty() {
                String::new()
            } else {
                format!(", {} TTL drifts", self.ttl_drifts.len())
            },
        )?;

        Ok(())
    }
}
