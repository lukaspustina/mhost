use crate::output::summary::SummaryOptions;
use crate::output::{Output, OutputConfig, OutputFormat};
use crate::resolver::Lookups;
use anyhow::{Context, Result};
use std::io;

pub fn output(lookups: &Lookups) -> Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    let opts = SummaryOptions::default();
    let config = OutputConfig::summary(opts);
    let output = Output::new(config);
    output
        .output(&mut handle, &lookups)
        .context("Failed to print summary to stdout.")
}
