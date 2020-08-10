use std::cmp::Ordering;
use std::io::Write;

use nom::lib::std::convert::TryFrom;

use crate::services::ripe_stats::RipeStatsResponse;
use crate::Result;
use crate::{Error, RecordType};
use serde::Serialize;

pub mod json;
pub mod summary;

pub static CAPTION_PREFIX: &str = "▶︎";
pub static INFO_PREFIX: &str = "▸";
pub static ITEMAZATION_PREFIX: &str = "∙";

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

pub trait OutputFormat<T> {
    fn output<W: Write>(&self, writer: &mut W, data: &T) -> Result<()>;
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

impl<T: Serialize + summary::SummaryFormatter> OutputFormat<T> for Output<'_> {
    fn output<W: Write>(&self, writer: &mut W, data: &T) -> Result<()> {
        match self.config {
            OutputConfig::Json { format } => format.output(writer, data),
            OutputConfig::Summary { format } => format.output(writer, data),
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
            RecordType::A => 6,
            RecordType::AAAA => 7,
            RecordType::ANAME => 8,
            RecordType::ANY => 9,
            RecordType::AXFR => 10,
            RecordType::CAA => 11,
            RecordType::IXFR => 12,
            RecordType::NAPTR => 13,
            RecordType::NULL => 14,
            RecordType::OPENPGPKEY => 15,
            RecordType::OPT => 16,
            RecordType::PTR => 17,
            RecordType::SRV => 18,
            RecordType::SSHFP => 19,
            RecordType::TLSA => 20,
            RecordType::DNSSEC => 21,
            RecordType::ZERO => 22,
            RecordType::Unknown(_) => 23,
        }
    }
}

impl Ordinal for &RipeStatsResponse {
    fn ordinal(&self) -> usize {
        match self {
            RipeStatsResponse::NetworkInfo { .. } => 1,
            RipeStatsResponse::Whois { .. } => 2,
            RipeStatsResponse::GeoLocation { .. } => 3,
            RipeStatsResponse::Error { .. } => 4,
        }
    }
}

pub mod styles {
    use lazy_static::lazy_static;
    use yansi::{Color, Style};

    lazy_static! {
        pub static ref EMPH: Style = Style::new(Color::White).bold();
    }
}
