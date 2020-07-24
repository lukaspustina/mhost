use crate::resolver::Lookups;
use std::io::Write;
use thiserror::Error;
use crate::RecordType;
use std::cmp::Ordering;

pub mod json;
pub mod summary;

#[derive(Debug, Error)]
pub enum OutputError {
    #[error("internal error: {msg}")]
    InternalError { msg: &'static str },
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

pub fn order_by_ordinal<T: Ordinal>(left: &T, right: &T) -> Ordering {
    left.ordinal().cmp(&right.ordinal())
}

pub trait Ordinal {
    fn ordinal(&self) -> usize;
}

impl Ordinal for RecordType {
    fn ordinal(&self) -> usize {
        match self {
            RecordType::SOA => 1,
            RecordType::NS => 2,
            RecordType::MX => 3,
            RecordType::TXT => 4,
            RecordType::CNAME => 5,
            RecordType::A => 5,
            RecordType::AAAA => 6,
            RecordType::ANAME => 7,
            RecordType::ANY => 8,
            RecordType::AXFR => 9,
            RecordType::CAA => 10,
            RecordType::IXFR => 11,
            RecordType::NAPTR => 12,
            RecordType::NULL => 13,
            RecordType::OPENPGPKEY => 14,
            RecordType::OPT => 15,
            RecordType::PTR => 16,
            RecordType::SRV => 17,
            RecordType::SSHFP => 18,
            RecordType::TLSA => 19,
            RecordType::DNSSEC => 20,
            RecordType::ZERO => 21,
            RecordType::Unknown(_) => 22,
        }
    }
}