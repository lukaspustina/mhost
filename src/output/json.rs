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

    #[test]
    fn json_serialization() {
        let config = OutputConfig::json();
        let output = Output::new(config);
        let lookups = Lookups::new(Vec::new());

        let mut buf = Vec::new();
        let res = output.output(&mut buf, &lookups);

        assert_that(&res).is_ok();
    }
}
