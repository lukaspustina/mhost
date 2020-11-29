use crate::output::{Output, OutputConfig, OutputFormat};
use anyhow::{Context, Result};
use std::io;

use crate::output::summary::SummaryFormatter;
use serde::Serialize;

pub fn output<T: Serialize + SummaryFormatter>(config: &OutputConfig, data: &T) -> Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    let output = Output::new(config);
    output
        .output(&mut handle, data)
        .context("Failed to print summary to stdout.")
}
