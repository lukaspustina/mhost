use lookup;
use statistics::Statistics;

use ansi_term::Colour;
use error_chain::ChainedError;
use itertools::Itertools;
use std::io::Write;
use std::fmt;
use tabwriter::TabWriter;
use trust_dns::rr::{RData, Record};

pub trait OutputModule {
    fn output(self) -> ();
}

pub struct DetailsOutput<'a> {
    responses: &'a [lookup::Result<lookup::Response>],
}

impl<'a> DetailsOutput<'a> {
    pub fn new(responses: &'a [lookup::Result<lookup::Response>]) -> Self {
        DetailsOutput { responses }
    }
}

impl<'a> OutputModule for DetailsOutput<'a> {
    fn output(self) -> () {
        for response in self.responses {
            match *response {
                Ok(ref x) => println!("{}", x),
                Err(ref e) => print_error(e),
            }
        }
    }
}

pub struct SummaryOutput<'a> {
    statistics: Statistics<'a>,
}

impl<'a> SummaryOutput<'a> {
    pub fn new(responses: &'a [lookup::Result<lookup::Response>]) -> Self {
        let statistics = Statistics::from(responses);
        SummaryOutput { statistics }
    }
}

impl<'a> OutputModule for SummaryOutput<'a> {
    fn output(self) -> () {
        println!("Received {} (min {}, max {} records) answers from {} servers",
                 self.statistics.num_of_ok_samples,
                 self.statistics.min_num_of_records,
                 self.statistics.max_num_of_records,
                 self.statistics.num_of_samples,
        );
        let records: Vec<_> = self.statistics
            .record_counts
            .values()
            .sorted_by(|a, b| compare_records(a.0, b.0))
            .iter()
            .map(|rr| {
                let record = DnsRecord(rr.0);
                let count = rr.1;
                format!("* {} ({})", record, count)
            })
            .collect();

        let mut tw = TabWriter::new(vec![]).padding(1);
        let _ = write!(&mut tw, "{}", records.join("\n"));
        let out_str = String::from_utf8(tw.into_inner().unwrap()).unwrap();

        println!("{}", out_str);
    }
}

impl fmt::Display for lookup::Response {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.answers.is_empty() {
            return write!(f, "DNS server {} has no records.", self.server);
        }
        let _ = write!(f, "DNS server {} responded with\n", self.server);
        let answers: Vec<String> = self
            .answers
            .iter()
            .sorted_by(|a, b| compare_records(a, b))
            .iter()
            .map(|answer| format!("* {}", DnsRecord(answer)))
            .collect();

        let mut tw = TabWriter::new(vec![]).padding(1);
        let _ = write!(&mut tw, "{}", answers.join("\n"));
        let out_str = String::from_utf8(tw.into_inner().unwrap()).unwrap();

        write!(f, "{}", out_str)
    }
}

fn compare_records(a: &Record, b: &Record) -> ::std::cmp::Ordering {
    let a = record_type_to_ordinal(a);
    let b = record_type_to_ordinal(b);

    a.cmp(&b)
}

fn record_type_to_ordinal(r: &Record) -> u16 {
    match *r.rdata() {
        RData::SOA(_) => 1000,
        RData::NS(_) => 2000,
        RData::MX(ref mx) => 3000 + mx.preference(),
        RData::TXT(_) => 4000,
        RData::CNAME(_) => 5000,
        RData::A(_) => 6000,
        RData::AAAA(_) => 7000,
        RData::PTR(_) => 8000,
        _ => ::std::u16::MAX,
    }
}

// Newtype pattern for Display implementation
pub struct DnsRecord<'a> (pub &'a Record);

impl<'a> fmt::Display for DnsRecord<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let DnsRecord(record) = *self;

        let str = match *record.rdata() {
            RData::A(ip) => format!("IPv4:\t{}", ip),
            RData::AAAA(ip) => format!("IPv6:\t{}", ip),
            RData::CNAME(ref name) => format!("CNAME:\t{}", Colour::Blue.paint(format!("{}", name))),
            RData::MX(ref mx) => {
                format!("MX:\t{} with preference {}",
                        Colour::Yellow.paint(format!("{}", mx.exchange())),
                        Colour::Yellow.paint(format!("{}", mx.preference()))
                )
            }
            RData::NS(ref name) => format!("NS:\t{}", Colour::Cyan.paint(format!("{}", name))),
            RData::SOA(ref soa) => {
                // TODO: time interval is in sec, use relative time
                format!("SOA:\torigin NS {}, responsible party {}, serial {}, refresh {} sec, retry {} sec, expire {} sec, min {} sec",
                        Colour::Green.paint(format!("{}", soa.mname())),
                        Colour::Green.paint(format!("{}", soa.rname())),
                        Colour::Green.paint(format!("{}", soa.serial())),
                        Colour::Green.paint(format!("{}", soa.refresh())),
                        Colour::Green.paint(format!("{}", soa.retry())),
                        Colour::Green.paint(format!("{}", soa.expire())),
                        Colour::Green.paint(format!("{}", soa.minimum()))
                    )
            }
            RData::TXT(ref txt) => format!("TXT:\t{}", Colour::Purple.paint(txt.txt_data().join(" "))),
            RData::PTR(ref ptr) => format!("PTR:\t{}", ptr.to_string()),
            ref x => format!(" * unclassified answer: {}", Colour::Red.paint(format!("{:?}", x))),
        };
        write!(f, "{}", str)
    }
}

pub fn print_error<T: ChainedError>(err: &T) {
    print!("{} ", err);
    for e in err.iter().skip(1) {
        print!("because {}", e);
    }
    println!();

    // The backtrace is only available if run with `RUST_BACKTRACE=1`.
    if let Some(backtrace) = err.backtrace() {
        println!("backtrace: {:?}", backtrace);
    }
}

error_chain! {
}
