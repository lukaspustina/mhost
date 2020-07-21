use super::*;

#[derive(Debug)]
pub struct JsonFormat {}

impl Default for JsonFormat {
    fn default() -> Self {
        JsonFormat {}
    }
}

impl OutputFormat for JsonFormat {
    fn output<W: Write>(&self, writer: &mut W, lookups: &Lookups) -> Result<()> {
        serde_json::to_writer_pretty(writer, lookups)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use spectral::prelude::*;

    use super::*;
    use std::io;

    #[test]
    fn json_serialization() {
        let config = OutputConfig::json();
        let output = Output::new(config);
        let lookups = Lookups::new(Vec::new());

        let stdout = io::stdout();
        let mut handle = stdout.lock();
        let res = output.output(&mut handle, &lookups);

        assert_that(&res).is_ok();
    }
}
