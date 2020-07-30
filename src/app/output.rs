use crate::app::Config;
use crate::output::{Output, OutputFormat};
use crate::resolver::Lookups;
use anyhow::{Context, Result};
use std::io;

pub fn output(config: &Config, lookups: &Lookups) -> Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    let output = Output::new(&config.output_config);
    output
        .output(&mut handle, &lookups)
        .context("Failed to print summary to stdout.")
}
