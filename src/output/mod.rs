use crate::resolver::Lookups;
use std::io::Write;
use thiserror::Error;

pub mod json;
pub mod summary;

#[derive(Debug, Error)]
pub enum OutputError {
    #[error("failed to write")]
    IoError {
        #[from]
        source: std::io::Error,
    },
    #[error("failed to serialize")]
    SerError {
        #[from]
        source: serde_json::Error,
    },
}

pub type Result<T> = std::result::Result<T, OutputError>;

#[derive(Debug)]
pub enum OutputType {
    Json,
    Summary,
}

pub trait OutputFormat {
    fn output<W: Write>(&self, writer: &mut W, lookups: &Lookups) -> Result<()>;
}

#[derive(Debug)]
pub enum OutputConfig {
    Json { format: json::JsonFormat },
    Summary { format: summary::SummaryFormat },
}

impl OutputConfig {
    pub fn json() -> Self {
        OutputConfig::Json {
            format: json::JsonFormat::default(),
        }
    }

    pub fn summary(opts: summary::SummaryOptions) -> Self {
        OutputConfig::Summary {
            format: summary::SummaryFormat::new(opts),
        }
    }
}

#[derive(Debug)]
pub struct Output {
    config: OutputConfig,
}

impl Output {
    pub fn new(config: OutputConfig) -> Output {
        Output { config }
    }
}

impl OutputFormat for Output {
    fn output<W: Write>(&self, writer: &mut W, lookups: &Lookups) -> Result<()> {
        match &self.config {
            OutputConfig::Json { format } => format.output(writer, lookups),
            OutputConfig::Summary { format } => format.output(writer, lookups),
        }
    }
}
