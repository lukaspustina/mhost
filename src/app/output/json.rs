use nom::lib::std::collections::HashSet;

use super::*;
use serde::Serialize;

#[derive(Debug)]
pub struct JsonOptions {
    /// Pretty formatting
    pretty: bool,
}

impl Default for JsonOptions {
    fn default() -> Self {
        JsonOptions { pretty: false }
    }
}

#[derive(Debug)]
pub struct JsonFormat {
    opts: JsonOptions,
}

impl JsonFormat {
    pub fn new(opts: JsonOptions) -> JsonFormat {
        JsonFormat { opts }
    }
}

impl Default for JsonFormat {
    fn default() -> Self {
        JsonFormat {
            opts: Default::default(),
        }
    }
}

impl<'a> TryFrom<Vec<&'a str>> for JsonOptions {
    type Error = Error;

    fn try_from(values: Vec<&'a str>) -> std::result::Result<Self, Self::Error> {
        let options: HashSet<&str> = values.into_iter().collect();
        Ok(JsonOptions {
            pretty: options.contains("pretty"),
        })
    }
}

impl<T: Serialize> OutputFormat<T> for JsonFormat {
    fn output<W: Write>(&self, writer: &mut W, data: &T) -> Result<()> {
        if self.opts.pretty {
            serde_json::to_writer_pretty(writer, data)?;
        } else {
            serde_json::to_writer(writer, data)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use spectral::prelude::*;

    use super::*;
    use crate::resolver::Lookups;

    #[test]
    fn json_serialization() {
        crate::utils::tests::logging::init();
        let opts = JsonOptions::default();
        let config = OutputConfig::json(opts);
        let output = Output::new(&config);
        let lookups = Lookups::new(Vec::new());

        let mut buf = Vec::new();
        let res = output.output(&mut buf, &lookups);

        assert_that(&res).is_ok();
    }
}
