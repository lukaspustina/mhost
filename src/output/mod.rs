use std::cmp::Ordering;
use std::io::Write;

use nom::lib::std::convert::TryFrom;

use crate::resolver::Lookups;
use crate::Result;
use crate::{Error, RecordType};

pub mod json;
pub mod summary;

#[derive(Debug, Clone, Copy)]
pub enum OutputType {
    Json,
    Summary,
}

impl TryFrom<&str> for OutputType {
    type Error = Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "json" => Ok(OutputType::Json),
            "summary" => Ok(OutputType::Summary),
            _ => Err(Error::ParserError {
                what: value.to_string(),
                to: "OutputType",
                why: "invalid output type".to_string(),
            }),
        }
    }
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
    pub fn json(opts: json::JsonOptions) -> Self {
        OutputConfig::Json {
            format: json::JsonFormat::new(opts),
        }
    }

    pub fn summary(opts: summary::SummaryOptions) -> Self {
        OutputConfig::Summary {
            format: summary::SummaryFormat::new(opts),
        }
    }
}

#[derive(Debug)]
pub struct Output<'a> {
    config: &'a OutputConfig,
}

impl Output<'_> {
    pub fn new(config: &OutputConfig) -> Output {
        Output { config }
    }
}

impl OutputFormat for Output<'_> {
    fn output<W: Write>(&self, writer: &mut W, lookups: &Lookups) -> Result<()> {
        match self.config {
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
