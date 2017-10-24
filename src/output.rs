use lookup;
use txt_records::{Spf, Word, Mechanism, Modifier};
use summary::{self, Summary};

use ansi_term::Colour;
use chrono::{Local, Duration};
use chrono_humanize::HumanTime;
use error_chain::ChainedError;
use itertools::Itertools;
use std::cmp::Ordering;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::io::{self, Write};
use tabwriter::TabWriter;
use trust_dns::rr::{RData, Record};

pub struct OutputConfig {
    pub human_readable: bool,
    pub show_headers: bool,
    pub show_nx_domain: bool,
    pub show_unsupported_rr: bool,
}

pub trait OutputModule {
    fn output(&self, w: &mut Write) -> Result<()>;
}

pub use self::json::Json;

mod json {
    use super::*;
    use lookup;

    use trust_dns::rr::RData;
    use serde_json;

    pub struct Json<'a> {
        responses: &'a [lookup::Result<lookup::Response>],
    }

    impl<'a> Json<'a> {
        pub fn new(responses: &'a [lookup::Result<lookup::Response>]) -> Self {
            Json { responses }
        }
    }

    impl<'a> OutputModule for Json<'a> {
        fn output(&self, mut w: &mut Write) -> Result<()> {
            let ok_responses: Vec<_> = self.responses
                .iter()
                .filter_map(|x| x.as_ref().ok())
                .collect();
            let rrs: Vec<_> = ok_responses
                .iter()
                .map(|response| {
                    let answers = response.answers
                        .iter()
                        .map(|r| {
                            match *r.rdata() {
                                RData::A(ip) => Some(RR::A(
                                    A { ip: format!("{}", ip), ttl: r.ttl() })),
                                RData::AAAA(ip) => Some(RR::AAAA(
                                    AAAA { ip: format!("{}", ip), ttl: r.ttl() })),
                                RData::CNAME(ref name) => Some(RR::CNAME(
                                    CNAME { name: format!("{}", name), ttl: r.ttl() })),
                                RData::MX(ref mx) => Some(RR::MX(
                                    MX { exchange: format!("{}", mx.exchange()), preference: mx.preference(), ttl: r.ttl() })),
                                RData::NS(ref name) => Some(RR::NS(
                                    NS { name: format!("{}", name), ttl: r.ttl() })),
                                RData::SOA(ref soa) => Some(RR::SOA(
                                    SOA {
                                        origin_server: format!("{}", soa.mname()),
                                        responsible_party: format!("{}", soa.rname()),
                                        serial: format!("{}", soa.serial()),
                                        refresh: soa.refresh(),
                                        retry: soa.retry(),
                                        expire: soa.expire(),
                                        minimum: soa.minimum(),
                                        ttl: r.ttl()
                                    })),
                                RData::TXT(ref txt) => Some(RR::TXT(
                                    TXT { txt: txt.txt_data().join(" "), ttl: r.ttl() })),
                                RData::PTR(ref ptr) => Some(RR::PTR(
                                    PTR { ptr: ptr.to_string(), ttl: r.ttl() })),
                                _ => None
                            }
                        })
                        .flat_map(|x| x)
                        .collect();
                    Response { server: format!("{}", response.server), answers }
                })
                .collect();

            serde_json::to_writer_pretty(&mut w, &rrs).chain_err(|| ErrorKind::OutputError)
        }
    }

    #[derive(Serialize)]
    struct Response {
        server: String,
        answers: Vec<RR>,
    }

    #[derive(Serialize)]
    enum RR {
        A(A),
        AAAA(AAAA),
        CNAME(CNAME),
        MX(MX),
        NS(NS),
        SOA(SOA),
        TXT(TXT),
        PTR(PTR)
    }

    #[derive(Serialize)]
    struct A {
        ip: String,
        ttl: u32,
    }

    #[derive(Serialize)]
    struct AAAA {
        ip: String,
        ttl: u32,
    }

    #[derive(Serialize)]
    struct CNAME {
        name: String,
        ttl: u32,
    }

    #[derive(Serialize)]
    struct MX {
        exchange: String,
        preference: u16,
        ttl: u32,
    }

    #[derive(Serialize)]
    struct NS {
        name: String,
        ttl: u32,
    }

    #[derive(Serialize)]
    struct SOA {
        origin_server: String,
        responsible_party: String,
        serial: String,
        refresh: i32,
        retry: i32,
        expire: i32,
        minimum: u32,
        ttl: u32,
    }

    #[derive(Serialize)]
    struct TXT {
        txt: String,
        ttl: u32,
    }

    #[derive(Serialize)]
    struct PTR {
        ptr: String,
        ttl: u32,
    }
}

pub struct DetailsOutput<'a> {
    cfg: &'a OutputConfig,
    responses: &'a [lookup::Result<lookup::Response>],
}

impl<'a> DetailsOutput<'a> {
    pub fn new(cfg: &'a OutputConfig, responses: &'a [lookup::Result<lookup::Response>]) -> Self {
        DetailsOutput { cfg, responses }
    }
}

impl<'a> OutputModule for DetailsOutput<'a> {
    fn output(&self, mut w: &mut Write) -> Result<()> {
        for response in self.responses {
            match *response {
                Ok(ref r) => write_response(&mut w, r, self.cfg)
                    .chain_err(|| ErrorKind::OutputError)?,
                Err(ref e) => print_error(&mut w, e)?,
            }
        }

        Ok(())
    }
}

pub struct SummaryOutput<'a> {
    cfg: &'a OutputConfig,
    summary: Summary<'a>,
}

impl<'a> SummaryOutput<'a> {
    pub fn new(cfg: &'a OutputConfig, responses: &'a [lookup::Result<lookup::Response>]) -> Self {
        let summary = Summary::from(responses);
        SummaryOutput { cfg, summary }
    }
}

impl<'a> OutputModule for SummaryOutput<'a> {
    fn output(&self, mut w: &mut Write) -> Result<()> {
        if self.cfg.show_headers {
            write!(&mut w, "Received {} (min {}, max {} records) answers from {} servers",
                   self.summary.num_of_ok_samples,
                   self.summary.min_num_of_records,
                   self.summary.max_num_of_records,
                   self.summary.num_of_samples,
            ).chain_err(|| ErrorKind::OutputError)?;
            if !self.summary.alerts.is_empty() {
                let msg = Colour::Red.bold().paint(
                    if self.summary.alerts.len() == 1 {
                        format!("{} alert", self.summary.alerts.len())
                    } else {
                        format!("{} alerts", self.summary.alerts.len())
                    });
                write!(&mut w, " and found {}", msg).chain_err(|| ErrorKind::OutputError)?;
            }
            writeln!(&mut w, ".").chain_err(|| ErrorKind::OutputError)?;
        }
        let records: Vec<_> = self.summary
            .record_counts
            .values()
            // TODO: Why do I need to specify a closure and not just a function?
            .sorted_by(|a, b| compare_records(a.0, b.0))
            .iter()
            .map(|rr| {
                let record = rr.0;
                let count = rr.1;
                (fmt_record(
                    record, self.cfg.human_readable, self.cfg.show_unsupported_rr),
                 count)
            })
            .filter(|&(ref rr, _)| rr.is_some())
            .map(|(rr, count)|
                format!("* {} ({})", rr.unwrap(), count)
            )
            .collect();

        let mut tw = TabWriter::new(vec![]).padding(1);
        write!(&mut tw, "{}", records.join("\n")).chain_err(|| ErrorKind::OutputError)?;
        let out_str = String::from_utf8(tw.into_inner().unwrap()).unwrap();
        writeln!(&mut w, "{}", out_str).chain_err(|| ErrorKind::OutputError)?;

        if !self.summary.alerts.is_empty() {
            writeln!(&mut w, "{}",
                     if self.summary.alerts.len() == 1 {
                         Colour::Red.bold().paint("Alert")
                     } else {
                         Colour::Red.bold().paint("Alert")
                     }
            ).chain_err(|| ErrorKind::OutputError)?;
            let alert_msgs: String = self.summary.alerts
                .iter()
                .map(|a| format!("* {}", a))
                .collect::<Vec<_>>()
                .join("\n");

            writeln!(&mut w, "{}", alert_msgs).chain_err(|| ErrorKind::OutputError)?;
        }

        Ok(())
    }
}

impl Display for summary::Alert {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match *self {
            summary::Alert::SoaSnDiverge(ref serials) =>
                write!(f, "SOA serial numbers diverge: {:?}", serials)
        }
    }
}

fn write_response(f: &mut Write, r: &lookup::Response, cfg: &OutputConfig) -> io::Result<()> {
    if r.answers.is_empty() {
        if cfg.show_nx_domain {
            return writeln!(f, "DNS server {} has no records.", r.server);
        } else {
            return ::std::result::Result::Ok(());
        }
    }
    if cfg.show_headers {
        let _ = write!(f, "DNS server {} responded with\n", r.server);
    }
    let answers: Vec<String> = r.answers
        .iter()
        .sorted_by(|a, b| compare_records(a, b))
        .iter()
        .map(|answer|
            (fmt_record(answer, cfg.human_readable, cfg.show_unsupported_rr),
             if cfg.human_readable {
                 humanize_ttl(answer.ttl() as i64)
             } else {
                 format!("in {} sec", answer.ttl())
             }
            )
        )
        .filter(|&(ref rr, _)| rr.is_some())
        .map(|(rr, ttl)|
            format!("* {} [expires {}]", rr.unwrap(), ttl)
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

fn fmt_record(r: &Record, human: bool, show_unsupported: bool) -> Option<String> {
    match *r.rdata() {
        RData::A(ip) => {
            Some(
                format!("IPv4:\t{}", ip)
            )
        }
        RData::AAAA(ip) => {
            Some(
                format!("IPv6:\t{}", ip)
            )
        }
        RData::CNAME(ref name) => {
            Some(
                format!("CNAME:\t{}", Colour::Blue.paint(format!("{}", name)))
            )
        }
        RData::MX(ref mx) => {
            Some(
                format!(
                    "MX:\t{} with preference {}",
                    Colour::Yellow.paint(format!("{}", mx.exchange())),
                    Colour::Yellow.paint(format!("{}", mx.preference()))
                )
            )
        }
        RData::NS(ref name) => {
            Some(
                format!("NS:\t{}", Colour::Cyan.paint(format!("{}", name)))
            )
        }
        RData::SOA(ref soa) => {
            Some(
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
            )
        }
        RData::TXT(ref txt) => {
            Some(
                format!("TXT:\t{}", Colour::Purple.paint(
                    if human {
                        fmt_txt(txt.txt_data())
                    } else {
                        txt.txt_data().join(" ")
                    }
                ))
            )
        }
        RData::PTR(ref ptr) => {
            Some(format!("PTR:\t{}", ptr))
        }
        ref x if show_unsupported => {
            Some(
                format!(
                    "Unsupported RR:\t{}",
                    Colour::Red.paint(format!("{:?}", x))
                )
            )
        }
        _ => None
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
