// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashMap;
use std::time::Duration;

use tabwriter::TabWriter;

use crate::resolver::Lookups;
use crate::resources::Record;
use crate::Error;

use super::*;
use crate::app::output::styles as output_styles;

impl SummaryFormatter for Lookups {
    fn output<W: Write>(&self, writer: &mut W, opts: &SummaryOptions) -> Result<()> {
        let mut rr_types: Vec<_> = self.record_types().into_iter().collect();
        rr_types.sort_by(order_by_ordinal);

        let mut tw = TabWriter::new(vec![]);

        for rr_type in rr_types {
            let records = self.records_by_type(rr_type);
            output_records(&mut tw, records, opts)?;
        }

        let text_buffer = tw.into_inner().map_err(|_| Error::InternalError {
            msg: "finish TabWriter buffer",
        })?;
        let out = String::from_utf8(text_buffer).map_err(|_| Error::InternalError {
            msg: "convert TabWriter buffer to output",
        })?;
        write!(writer, "{}", out)?;

        Ok(())
    }
}

fn output_records<W: Write>(writer: &mut W, records: Vec<&Record>, opts: &SummaryOptions) -> Result<()> {
    let records_counted = summarize_records(records);

    for (r, set) in records_counted {
        let mut suffix = if opts.condensed() {
            "".to_string()
        } else {
            let ttls: Vec<_> = set.iter().map(|x| x.ttl()).collect();
            let ttl_summary = crate::statistics::Summary::summary(ttls.as_slice());

            let ttl = format_ttl_summary(&ttl_summary, opts);
            format!(" {} ({})", ttl, set.len())
        };

        if opts.show_domain_names() {
            if opts.human() {
                suffix = format!("{} for domain name {}", suffix, r.name())
            } else {
                suffix = format!("{} q={}", suffix, r.name())
            }
        }

        writeln!(
            writer,
            " {} {}",
            output_styles::itemization_prefix(),
            r.render_with_suffix(&suffix, opts)
        )?;
    }

    Ok(())
}

//noinspection RsExternalLinter
fn summarize_records(records: Vec<&Record>) -> HashMap<&Record, Vec<&Record>> {
    let mut records_set: HashMap<&Record, Vec<&Record>> = HashMap::new();
    for r in records {
        let set = records_set.entry(r).or_default();
        set.push(r)
    }
    records_set
        .into_iter()
        .map(|(k, v)| (k, v.into_iter().collect()))
        .collect()
}

fn format_ttl_summary(summary: &crate::statistics::Summary<u32>, opts: &SummaryOptions) -> String {
    let ttl_min = summary.min.unwrap_or(0) as u64;
    let ttl_max = summary.max.unwrap_or(0) as u64;

    match (opts.human(), ttl_min == ttl_max) {
        (true, true) => format!(
            "expires in {}",
            humantime::format_duration(Duration::from_secs(ttl_min))
        ),
        (true, false) => format!(
            "expires in [min {}, max {}]",
            humantime::format_duration(Duration::from_secs(ttl_min)),
            humantime::format_duration(Duration::from_secs(ttl_max)),
        ),
        (false, true) => format!("TTL={}", ttl_min),
        (false, false) => format!("TTL=[{}, {}]", ttl_min, ttl_max),
    }
}

#[cfg(test)]
mod tests {
    use spectral::prelude::*;

    use super::*;

    #[test]
    fn summary() {
        crate::utils::tests::logging::init();
        let opts = SummaryOptions::default();
        let config = OutputConfig::summary(opts);
        let output = Output::new(&config);
        let lookups = Lookups::new(Vec::new());

        let mut buf = Vec::new();
        let res = output.output(&mut buf, &lookups);

        assert_that(&res).is_ok();
    }
}
