use super::*;

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
    fn output<W: Write>(&self, _writer: &mut W, _lookups: &Lookups) -> Result<()> {
        Ok(())
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
