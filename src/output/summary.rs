use super::*;
use crate::resources::rdata::MX;
use crate::RecordType;
use std::net::Ipv4Addr;
use tabwriter::TabWriter;

#[derive(Debug)]
pub struct SummaryOptions {}

impl Default for SummaryOptions {
    fn default() -> Self {
        SummaryOptions {}
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
            match rr_type {
                RecordType::A => do_output(&mut tw, lookups.a())?,
                RecordType::MX => do_output(&mut tw, lookups.mx())?,
                _ => (),
            };
        }
        // TODO: unwrap, unwrap
        let out = String::from_utf8(tw.into_inner().unwrap()).unwrap();
        writeln!(writer, "{}", out)?;

        Ok(())
    }
}

fn do_output<W: Write, T: Ord + Render>(writer: &mut W, mut lookups: Vec<&T>) -> Result<()> {
    lookups.sort();
    for l in lookups {
        writeln!(writer, "* {}", l.render())?;
    }

    Ok(())
}

trait Render {
    fn render(&self) -> String;
}

impl Render for Ipv4Addr {
    fn render(&self) -> String {
        format!("A:\t{}", styles::A.paint(self.to_string()))
    }
}

impl Render for MX {
    fn render(&self) -> String {
        format!(
            "MX:\t{} with preference {}",
            styles::MX.paint(self.exchange()),
            styles::MX.paint(self.preference())
        )
    }
}

mod styles {
    use lazy_static::lazy_static;
    use yansi::{Color, Style};
    lazy_static! {
        pub static ref A: Style = Style::new(Color::White).bold();
        pub static ref MX: Style = Style::new(Color::Yellow);
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
