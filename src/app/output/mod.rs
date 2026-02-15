// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::cmp::Ordering;
use std::io::{self, Write};

use std::convert::TryFrom;

use crate::services::whois::WhoisResponse;
use crate::{Error, RecordType, Result};
use serde::Serialize;

pub mod json;
pub mod records;
pub mod styles;
pub mod summary;

pub fn output<T: Serialize + summary::SummaryFormatter>(config: &OutputConfig, data: &T) -> Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    Output::new(config).output(&mut handle, data)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    pub fn new(config: &OutputConfig) -> Output<'_> {
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
            RecordType::ANY => 5,
            RecordType::AXFR => 6,
            RecordType::CAA => 7,
            RecordType::IXFR => 8,
            RecordType::NAPTR => 9,
            RecordType::OPENPGPKEY => 10,
            RecordType::OPT => 11,
            RecordType::SSHFP => 12,
            RecordType::TLSA => 13,
            RecordType::DNSSEC => 14,
            RecordType::HINFO => 15,
            RecordType::HTTPS => 16,
            RecordType::SVCB => 17,
            RecordType::ZERO => 18,
            RecordType::CNAME => 19,
            RecordType::A => 20,
            RecordType::AAAA => 21,
            RecordType::ANAME => 22,
            RecordType::PTR => 23,
            RecordType::SRV => 24,
            RecordType::NULL => 25,
            RecordType::Unknown(_) => 26,
        }
    }
}

impl Ordinal for &WhoisResponse {
    fn ordinal(&self) -> usize {
        match self {
            WhoisResponse::NetworkInfo { .. } => 1,
            WhoisResponse::Whois { .. } => 2,
            WhoisResponse::GeoLocation { .. } => 3,
            WhoisResponse::Error { .. } => 4,
        }
    }
}
