use lookup;
use txt_records::{Spf, Word, Mechanism, Modifier};
use statistics::Statistics;

use ansi_term::Colour;
use chrono::{Local, Duration};
use chrono_humanize::HumanTime;
use error_chain::ChainedError;
use itertools::Itertools;
use std::cmp::Ordering;
use std::io::{self, Write};
use tabwriter::TabWriter;
use trust_dns::rr::{RData, Record};

pub trait OutputModule {
    fn output(&self, w: &mut Write) -> Result<()>;
    fn is_human(&self) -> bool;
}

pub struct DetailsOutput<'a> {
    responses: &'a [lookup::Result<lookup::Response>],
    human: bool,
}

impl<'a> DetailsOutput<'a> {
    pub fn new(responses: &'a [lookup::Result<lookup::Response>], human: bool) -> Self {
        DetailsOutput { responses, human }
    }
}

impl<'a> OutputModule for DetailsOutput<'a> {
    fn output(&self, w: &mut Write) -> Result<()> {
        for response in self.responses {
            match *response {
                Ok(ref r) => write_response(w, r, self.human).chain_err(|| ErrorKind::OutputError)?,
                Err(ref e) => print_error(w, e)?,
            }
        }

        Ok(())
    }

    fn is_human(&self) -> bool {
        self.human
    }
}

pub struct SummaryOutput<'a> {
    statistics: Statistics<'a>,
    human: bool,
}

impl<'a> SummaryOutput<'a> {
    pub fn new(responses: &'a [lookup::Result<lookup::Response>], human: bool) -> Self {
        let statistics = Statistics::from(responses);
        SummaryOutput { statistics, human }
    }
}

impl<'a> OutputModule for SummaryOutput<'a> {
    fn output(&self, w: &mut Write) -> Result<()> {
        writeln!(w, "Received {} (min {}, max {} records) answers from {} servers",
                 self.statistics.num_of_ok_samples,
                 self.statistics.min_num_of_records,
                 self.statistics.max_num_of_records,
                 self.statistics.num_of_samples,
        ).chain_err(|| ErrorKind::OutputError)?;
        let records: Vec<_> = self.statistics
            .record_counts
            .values()
            // TODO: Why do I need to specify a closure and not just a function?
            .sorted_by(|a, b| compare_records(a.0, b.0))
            .iter()
            .map(|rr| {
                let record = rr.0;
                let count = rr.1;
                format!("* {} ({})", fmt_record(record, self.human), count)
            })
            .collect();

        let mut tw = TabWriter::new(vec![]).padding(1);
        write!(&mut tw, "{}", records.join("\n")).chain_err(|| ErrorKind::OutputError)?;
        let out_str = String::from_utf8(tw.into_inner().unwrap()).unwrap();

        writeln!(w, "{}", out_str).chain_err(|| ErrorKind::OutputError)?;

        Ok(())
    }

    fn is_human(&self) -> bool {
        self.human
    }
}

fn write_response(f: &mut Write, r: &lookup::Response, human: bool) -> io::Result<()> {
    if r.answers.is_empty() {
        return writeln!(f, "DNS server {} has no records.", r.server);
    }
    let _ = write!(f, "DNS server {} responded with\n", r.server);
    let answers: Vec<String> = r.answers
        .iter()
        .sorted_by(|a, b| compare_records(a, b))
        .iter()
        .map(|answer|
            format!("* {} [expires {}]",
                    fmt_record(answer, human),
                    if human {
                        humanize_ttl(answer.ttl() as i64)
                    } else {
                        format!("in {} sec", answer.ttl())
                    }
            )
        )
        .collect();

    let mut tw = TabWriter::new(vec![]).padding(1);
    let _ = write!(&mut tw, "{}", answers.join("\n"));
    let out_str = String::from_utf8(tw.into_inner().unwrap()).unwrap();

    writeln!(f, "{}", out_str)
}


fn compare_records(a: &Record, b: &Record) -> Ordering {
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

fn humanize_ttl(ttl: i64) -> String {
    let dt = Local::now() + Duration::seconds(ttl);
    let ht = HumanTime::from(dt);

    format!("{}", ht)
}

fn fmt_record(r: &Record, human: bool) -> String {
    match *r.rdata() {
        RData::A(ip) => format!("IPv4:\t{}", ip),
        RData::AAAA(ip) => format!("IPv6:\t{}", ip),
        RData::CNAME(ref name) => {
            format!("CNAME:\t{}", Colour::Blue.paint(format!("{}", name)))
        }
        RData::MX(ref mx) => {
            format!(
                "MX:\t{} with preference {}",
                Colour::Yellow.paint(format!("{}", mx.exchange())),
                Colour::Yellow.paint(format!("{}", mx.preference()))
            )
        }
        RData::NS(ref name) => format!("NS:\t{}", Colour::Cyan.paint(format!("{}", name))),
        RData::SOA(ref soa) => {
            if human {
                format!(
                    "SOA:\torigin NS {}, responsible party {}, serial {}, refresh {}, retry {}, expire {}, min {}",
                    Colour::Green.paint(format!("{}", soa.mname())),
                    Colour::Green.paint(format!("{}", soa.rname())),
                    Colour::Green.paint(format!("{}", soa.serial())),
                    Colour::Green.paint(humanize_ttl(soa.refresh() as i64)),
                    Colour::Green.paint(humanize_ttl(soa.retry() as i64)),
                    Colour::Green.paint(humanize_ttl(soa.expire() as i64)),
                    Colour::Green.paint(humanize_ttl(soa.minimum() as i64))
                )
            } else {
                format!(
                    "SOA:\torigin NS {}, responsible party {}, serial {}, refresh {} sec, retry {} sec, expire {} sec, min {} sec",
                    Colour::Green.paint(format!("{}", soa.mname())),
                    Colour::Green.paint(format!("{}", soa.rname())),
                    Colour::Green.paint(format!("{}", soa.serial())),
                    Colour::Green.paint(format!("{}", soa.refresh())),
                    Colour::Green.paint(format!("{}", soa.retry())),
                    Colour::Green.paint(format!("{}", soa.expire())),
                    Colour::Green.paint(format!("{}", soa.minimum()))
                )

            }
        }
        RData::TXT(ref txt) => {
            format!("TXT:\t{}", Colour::Purple.paint(
                if human {
                    fmt_txt(txt.txt_data())
                } else {
                    txt.txt_data().join(" ")
                }
            ))
        }
        RData::PTR(ref ptr) => format!("PTR:\t{}", ptr.to_string()),
        ref x => {
            format!(
                "Unsupported RR:\t{}",
                Colour::Red.paint(format!("{:?}", x))
            )
        }
    }
}

fn fmt_txt(txts: &[String]) -> String {
    let fmts: Vec<_> = txts
        .iter()
        .map(|txt| {
            if let Ok(spf) = Spf::from_str(txt) {
                fmt_txt_spf(&spf)
            } else {
                txt.to_string()
            }
        })
        .collect();
    fmts.iter().join("\t* ")
}

fn fmt_txt_spf(spf: &Spf) -> String {
    let words: Vec<_> = spf.words
        .iter()
        .map(|w| {
            match *w {
                Word::Word(ref q, Mechanism::All) => format!("{:?} for all", q),
                Word::Word(ref q, Mechanism::A) => format!("{:?} for A/AAAA record", q),
                Word::Word(ref q, Mechanism::IPv4(range)) if range.contains('/') => format!("{:?} for IPv4 range {}", q, range),
                Word::Word(ref q, Mechanism::IPv4(range)) => format!("{:?} for IPv4 {}", q, range),
                Word::Word(ref q, Mechanism::IPv6(range)) if range.contains('/') => format!("{:?} for IPv6 range {}", q, range),
                Word::Word(ref q, Mechanism::IPv6(range)) => format!("{:?} for IPv6 {}", q, range),
                Word::Word(ref q, Mechanism::MX) => format!("{:?} for mail exchanges", q),
                Word::Word(ref q, Mechanism::PTR) => format!("{:?} for reverse mapping", q),
                Word::Word(ref q, Mechanism::Exists(domain)) => format!("{:?} for A/AAAA record according to {}", q, domain),
                Word::Word(ref q, Mechanism::Include(domain)) => format!("{:?} for include from {}", q, domain),
                Word::Modifier(Modifier::Redirect(query)) => format!("redirect to query {}", query),
                Word::Modifier(Modifier::Exp(explanation)) => format!("explanation according to {}", explanation),
            }
        })
        .collect();
    format!("SPF version: {}\n\t* {}", spf.version, words.join("\n\t* "))
}

pub fn print_error<T: ChainedError>(w: &mut Write, err: &T) -> Result<()> {
    write!(w, "{} ", err).chain_err(|| ErrorKind::OutputError)?;
    for e in err.iter().skip(1) {
        write!(w, "because {}", e).chain_err(|| ErrorKind::OutputError)?;
    }
    writeln!(w).chain_err(|| ErrorKind::OutputError)?;

    // The backtrace is only available if run with `RUST_BACKTRACE=1`.
    if let Some(backtrace) = err.backtrace() {
        writeln!(w, "backtrace: {:?}", backtrace).chain_err(|| ErrorKind::OutputError)?;
    }

    Ok(())
}

error_chain! {
    errors {
        OutputError {
            description("Failed to write output")
            display("Failed to write output")
        }
    }
}
