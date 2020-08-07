use crate::app::GlobalConfig;
use crate::output::{Output, OutputFormat};
use anyhow::{Context, Result};
use std::io;

use crate::output::summary::SummaryFormatter;
use serde::Serialize;

pub fn output<T: Serialize + SummaryFormatter>(config: &GlobalConfig, data: &T) -> Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    let output = Output::new(&config.output_config);
    output
        .output(&mut handle, data)
        .context("Failed to print summary to stdout.")
}
