use super::*;
use crate::resources::rdata::{Name, MX, SOA, TXT};
use crate::resources::Record;
use crate::RecordType;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tabwriter::TabWriter;

#[derive(Debug)]
pub struct SummaryOptions {
    human: bool,
}

impl Default for SummaryOptions {
    fn default() -> Self {
        SummaryOptions { human: false }
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

impl OutputFormat for SummaryFormat {
    fn output<W: Write>(&self, writer: &mut W, lookups: &Lookups) -> Result<()> {
        let mut rr_types: Vec<_> = lookups.record_types().into_iter().collect();
        rr_types.sort();

        let mut tw = TabWriter::new(vec![]);

        for rr_type in rr_types {
            let records = lookups.records_by_type(rr_type);
            do_output(&mut tw, records, &self.opts)?;
        }

        let text_buffer = tw.into_inner().map_err(|_| OutputError::InternalError {
            msg: "finish TabWriter buffer",
        })?;
        let out = String::from_utf8(text_buffer).map_err(|_| OutputError::InternalError {
            msg: "convert TabWriter buffer to output",
        })?;
        writeln!(writer, "{}", out)?;

        Ok(())
    }
}

fn do_output<W: Write>(writer: &mut W, records: Vec<&Record>, opts: &SummaryOptions) -> Result<()> {
    let records_counted = summarize_records(records);
    for (r, count) in records_counted {
        writeln!(writer, "* {} ({})", r.render(opts), count)?;
    }

    Ok(())
}

fn summarize_records(records: Vec<&Record>) -> HashMap<&Record, usize> {
    let mut records_counted: HashMap<&Record, usize> = HashMap::new();
    for r in records {
        let count = records_counted.entry(r).or_insert(0);
        *count += 1;
    }
    records_counted
}

trait Rendering {
    fn render(&self, opts: &SummaryOptions) -> String;
}

impl Rendering for Record {
    fn render(&self, opts: &SummaryOptions) -> String {
        let ttl = if opts.human {
            format!(
                "expires in {}",
                humantime::format_duration(Duration::from_secs(self.ttl() as u64))
            )
        } else {
            format!("TTL={}", self.ttl())
        };

        match self.rr_type() {
            RecordType::A => format!("A:\t{}, {}", self.rdata().a().unwrap().render(opts), ttl),
            RecordType::AAAA => format!("AAAA:\t{}, {}", self.rdata().aaaa().unwrap().render(opts), ttl),
            RecordType::CNAME => format!("CNAME:\t{}, {}", self.rdata().cname().unwrap().render(opts), ttl),
            RecordType::MX => format!("MX:\t{}, {}", self.rdata().mx().unwrap().render(opts), ttl),
            RecordType::SOA => format!("SOA:\t{}, {}", self.rdata().soa().unwrap().render(opts), ttl),
            RecordType::TXT => format!("TXT:\t{}, {}", self.rdata().txt().unwrap().render(opts), ttl),
            rr_type => format!("{}:\t<not yet implemented>", rr_type),
        }
    }
}

impl Rendering for Ipv4Addr {
    fn render(&self, _: &SummaryOptions) -> String {
        styles::A.paint(self).to_string()
    }
}

impl Rendering for Ipv6Addr {
    fn render(&self, _: &SummaryOptions) -> String {
        styles::AAAA.paint(self).to_string()
    }
}

impl Rendering for Name {
    fn render(&self, _: &SummaryOptions) -> String {
        styles::NAME.paint(self).to_string()
    }
}

impl Rendering for MX {
    fn render(&self, _: &SummaryOptions) -> String {
        format!(
            "{}\twith preference {}",
            styles::MX.paint(self.exchange()),
            styles::MX.paint(self.preference()),
        )
    }
}

impl Rendering for SOA {
    fn render(&self, opts: &SummaryOptions) -> String {
        if opts.human {
            self.human(opts)
        } else {
            self.plain(opts)
        }
    }
}

impl SOA {
    fn human(&self, _: &SummaryOptions) -> String {
        let refresh = humantime::format_duration(Duration::from_secs(self.refresh() as u64));
        let retry = humantime::format_duration(Duration::from_secs(self.retry() as u64));
        let expire = humantime::format_duration(Duration::from_secs(self.expire() as u64));
        let minimum = humantime::format_duration(Duration::from_secs(self.minimum() as u64));
        format!(
            "origin NS {}, responsible party {}, serial {}, refresh {}, retry {}, expire {}, negative response TTL {}",
            styles::SOA.paint(self.mname()),
            styles::SOA.paint(self.rname()),
            styles::SOA.paint(self.serial()),
            styles::SOA.paint(refresh),
            styles::SOA.paint(retry),
            styles::SOA.paint(expire),
            styles::SOA.paint(minimum),
        )
    }

    fn plain(&self, _: &SummaryOptions) -> String {
        format!(
            "mname {}, rname {}, serial {}, refresh in {}, retry in {}, expire in {}, negative response TTL {}",
            styles::SOA.paint(self.mname()),
            styles::SOA.paint(self.rname()),
            styles::SOA.paint(self.serial()),
            styles::SOA.paint(self.refresh()),
            styles::SOA.paint(self.retry()),
            styles::SOA.paint(self.expire()),
            styles::SOA.paint(self.minimum()),
        )
    }
}

impl Rendering for TXT {
    fn render(&self, opts: &SummaryOptions) -> String {
        if opts.human {
            self.human(opts)
        } else {
            self.plain(opts)
        }
    }
}

impl TXT {
    fn human(&self, _: &SummaryOptions) -> String {
        styles::TXT.paint("<human output not yet implemented>").to_string()
    }

    fn plain(&self, _: &SummaryOptions) -> String {
        let mut buf = String::new();
        for item in self.iter() {
            let str = String::from_utf8_lossy(item);
            buf.push_str(&str);
        }

        format!("'{}'", styles::TXT.paint(&buf))
    }
}

mod styles {
    use lazy_static::lazy_static;
    use yansi::{Color, Style};
    lazy_static! {
        pub static ref A: Style = Style::new(Color::White).bold();
        pub static ref AAAA: Style = Style::new(Color::White).bold();
        pub static ref MX: Style = Style::new(Color::Yellow);
        pub static ref NAME: Style = Style::new(Color::Blue);
        pub static ref SOA: Style = Style::new(Color::Green);
        pub static ref TXT: Style = Style::new(Color::Magenta);
    }
}

#[cfg(test)]
mod tests {
    use spectral::prelude::*;

    use super::*;
    use std::io;

    #[test]
    fn summary() {
        let opts = SummaryOptions::default();
        let config = OutputConfig::summary(opts);
        let output = Output::new(config);
        let lookups = Lookups::new(Vec::new());

        let stdout = io::stdout();
        let mut handle = stdout.lock();
        let res = output.output(&mut handle, &lookups);

        assert_that(&res).is_ok();
    }
}
