use lookup;
use statistics::Statistics;

use ansi_term::Colour;
use error_chain::ChainedError;
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
        let mut records: Vec<_> = self.statistics
            .record_counts
            .values()
            .map(|rr| {
                let record = DnsRecord(rr.0);
                let count = rr.1;
                format!("* {} ({})", record, count)
            })
            .collect();
        records.sort();

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
        let mut answers: Vec<String> = self
            .answers
            .iter()
            .map(|answer| format!("* {}", DnsRecord(answer)))
            .collect();
        answers.sort();

        let mut tw = TabWriter::new(vec![]).padding(1);
        let _ = write!(&mut tw, "{}", answers.join("\n"));
        let out_str = String::from_utf8(tw.into_inner().unwrap()).unwrap();

        write!(f, "{}", out_str)
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
                        Colour::Yellow.paint(format!("{}",mx.preference()))
                )
            }
            RData::NS(ref name) => format!("NS:\t{}", Colour::Cyan.paint(format!("{}", name))),
            RData::SOA(ref soa) => {
                format!("SOA:\t{}", Colour::Green.paint(
                    format!(
                        "{} {} {} {} {} {} {}",
                        soa.mname(),
                        soa.rname(),
                        soa.serial(),
                        soa.refresh(),
                        soa.retry(),
                        soa.expire(),
                        soa.minimum()
                    )))
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
