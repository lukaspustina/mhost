#[macro_use]
extern crate clap;
#[macro_use]
extern crate error_chain;
extern crate mhost;
extern crate resolv_conf;
extern crate tokio_core;
extern crate trust_dns;

use mhost::{multiple_lookup, Statistics, Query, Response};
use mhost::lookup::Result as LookupResult;

use clap::{App, Arg, ArgMatches, Shell};
use error_chain::ChainedError;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio_core::reactor::Core;
use trust_dns::rr::{RData, RecordType};

// Arbitrary list of public DNS servers
static DEFAULT_DNS_SERVERS: &'static [&str] = &[
    // "Level3",
    "209.244.0.3",
    "209.244.0.4",
    // "Verisign",
    "64.6.64.6",
    "64.6.65.6",
    // "Google",
    "8.8.8.8",
    "8.8.4.4",
    // "DNS.WATCH",
    "84.200.69.80",
    "84.200.70.40",
    // "OpenDNS Home",
    "208.67.222.222",
    "208.67.220.220",
    // "SafeDNS",
    "195.46.39.39",
    "195.46.39.40",
    // "Dyn",
    "216.146.35.35",
    "216.146.36.36",
    // "FreeDNS",
    "37.235.1.174",
    "37.235.1.177",
    // "Alternate DNS",
    "198.101.242.72",
    "23.253.163.53",
];

static DEFAULT_RECORD_TYPES: &'static [&str] = &["a", "aaaa", "mx"];

fn run() -> Result<()> {
    let args = build_cli().get_matches();

    if args.is_present("completions") {
        return generate_completion(&args);
    }

    let dns_endpoints = get_dns_servers(&args)
        .chain_err(|| ErrorKind::ServerIpAddrParsingError)?
        .into_iter()
        .map(|s| (s, 53))
        .collect();

    let timeout = value_t!(args, "timeout", u64)
        .map(Duration::from_secs)
        .unwrap();

    let mut query = match IpAddr::from_str(args.value_of("domain name").unwrap()) {
        Ok(ip) => Query::from(ip, vec![RecordType::PTR]),
        Err(_) => {
            let record_types = get_record_types(&args).chain_err(|| {
                ErrorKind::ResoureRecordTypeParsingError
            })?;
            Query::new(args.value_of("domain name").unwrap(), record_types)
        }
    };
    query = query.set_timeout(timeout);

    let mut io_loop = Core::new().unwrap();
    let lookup = multiple_lookup(&io_loop.handle(), query, dns_endpoints);
    let result = io_loop.run(lookup);

    let responses = result.as_ref().unwrap();

    for output in args.values_of_lossy("output module").unwrap() {
        match output.as_ref() {
            "details" => DetailsOutput::new(responses).output(),
            _ => SummaryOutput::new(responses).output(),
        }
    }

    Ok(())
}

trait OutputModule {
    fn output(self) -> ();
}

struct DetailsOutput<'a> {
    responses: &'a [LookupResult<Response>],
}

impl<'a> DetailsOutput<'a> {
    pub fn new(responses: &'a [LookupResult<Response>]) -> Self {
        DetailsOutput { responses }
    }
}

impl<'a> OutputModule for DetailsOutput<'a> {
    fn output(self) -> () {
        for response in self.responses {
            match *response {
                Ok(ref x) => println!("{}", DnsResponse(x)),
                Err(ref e) => print_error(e),
            }
        }
    }
}

struct SummaryOutput<'a> {
    statistics: Statistics<'a>,
}

impl<'a> SummaryOutput<'a> {
    pub fn new(responses: &'a [LookupResult<Response>]) -> Self {
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
                format!("{} ({})", record, count)
            })
            .collect();
        records.sort();
        for r in records {
            println!("* {}", r);
        }
        if !self.statistics.failures.is_empty() {
            println!("Failures");
            for f in self.statistics.failures {
                print!("* ");
                print_error(f);
            }
        }
    }
}


fn build_cli() -> App<'static, 'static> {
    let name = env!("CARGO_PKG_NAME");
    let version = env!("CARGO_PKG_VERSION");
    let about = env!("CARGO_PKG_DESCRIPTION");

    App::new(name)
        .version(version)
        .about(about)
        .arg(
            Arg::with_name("domain name")
                .index(1)
                .required(true)
                .conflicts_with("completions")
                .help("domain name or IP address to look up")
        )
        .arg(
            Arg::with_name("timeout")
                .long("timeout")
                .default_value("5")
                .help("Sets timeout for server responses in sec")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("record types")
                .long("type")
                .short("t")
                .takes_value(true)
                .multiple(true)
                .require_delimiter(true)
                .possible_values(
                    &[
                        "a",
                        "aaaa",
                        "any",
                        "cname",
                        "dnskey",
                        "mx",
                        "ns",
                        "opt",
                        "ptr",
                        "soa",
                        "srv",
                        "txt",
                    ],
                )
                .help("Selects resource record type [default: a, aaaa, mx]")
        )
        .arg(
            Arg::with_name("dont use local dns servers")
                .short("L")
                .help("Do not use local (/etc/resolv.conf) DNS servers")
        )
        .arg(Arg::with_name("predefined server").short("p").help(
            "Uses predefined DNS servers set"
        ))
        .arg(
            Arg::with_name("DNS servers")
                .long("server")
                .short("s")
                .takes_value(true)
                .multiple(true)
                .require_delimiter(true)
                .number_of_values(1)
                .help(
                    "Sets DNS servers to use"
                )
        )
        .arg(
            Arg::with_name("output module")
                .long("module")
                .short("m")
                .takes_value(true)
                .multiple(true)
                .require_delimiter(true)
                .default_value("summary")
                .possible_values(
                    &[
                        "summary",
                        "details",
                    ],
                )
                .help("Selects output module")
        )
        .arg(
            Arg::with_name("completions")
                .long("completions")
                .takes_value(true)
                .hidden(true)
                .possible_values(&["bash", "fish", "zsh"])
                .help("The shell to generate the script for")
        )
}

fn generate_completion(args: &ArgMatches) -> Result<()> {
    let bin_name = env!("CARGO_PKG_NAME");
    let shell = args.value_of("completions").ok_or(
        ErrorKind::CliArgsParsingError,
    )?;
    build_cli().gen_completions_to(
        bin_name,
        shell.parse::<Shell>().unwrap(),
        &mut std::io::stdout(),
    );
    Ok(())
}

fn get_local_dns_servers() -> Result<Vec<IpAddr>> {
    let mut buf = Vec::with_capacity(4096);
    let mut f = File::open("/etc/resolv.conf").chain_err(
        || ErrorKind::ResolvConfError,
    )?;
    f.read_to_end(&mut buf).unwrap();
    let cfg = resolv_conf::Config::parse(&buf[..]).chain_err(|| {
        ErrorKind::ResolvConfError
    })?;
    Ok(cfg.nameservers)
}

fn get_dns_servers(args: &ArgMatches) -> Result<Vec<IpAddr>> {
    let mut dns_servers: Vec<IpAddr> = Vec::new();
    if let Some(servers) = args.values_of_lossy("DNS servers") {
        dns_servers.extend(servers.into_iter().map(|server| {
            IpAddr::from_str(&server).unwrap()
        }));
    }
    if args.is_present("predefined server") {
        dns_servers.extend(DEFAULT_DNS_SERVERS.iter().map(|server| {
            IpAddr::from_str(server).unwrap()
        }));
    }
    if !args.is_present("dont use local dns servers") {
        dns_servers.extend(get_local_dns_servers()?);
    }

    Ok(dns_servers)
}

fn get_record_types(args: &ArgMatches) -> Result<Vec<RecordType>> {
    let record_types = if let Some(record_types) = args.values_of_lossy("record types") {
        record_types
            .iter()
            .map(|rt| RecordType::from_str(&rt.to_uppercase()).unwrap())
            .collect()
    } else {
        DEFAULT_RECORD_TYPES
            .iter()
            .map(|rt| RecordType::from_str(&rt.to_uppercase()).unwrap())
            .collect()
    };

    Ok(record_types)
}

// Newtype pattern for Display implementation
struct DnsResponse<'a>(pub &'a mhost::Response);

// Display impl for plain, basic output
impl<'a> fmt::Display for DnsResponse<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let DnsResponse(dns_response) = *self;
        if dns_response.answers.is_empty() {
            return write!(f, "DNS server {} has no records.", dns_response.server);
        }
        let _ = write!(f, "DNS server {} responded with\n", dns_response.server);
        let mut answers: Vec<String> = dns_response
            .answers
            .iter()
            .map(|answer| format!("* {}", DnsRecord(answer)))
            .collect();
        answers.sort();
        write!(f, "{}", answers.join("\n"))
    }
}

// Newtype pattern for Display implementation
struct DnsRecord<'a>(pub &'a trust_dns::rr::Record);

impl<'a> fmt::Display for DnsRecord<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let DnsRecord(record) = *self;

        let str = match *record.rdata() {
            RData::A(ip) => format!("IPv4: {}", ip),
            RData::AAAA(ip) => format!("IPv6: {}", ip),
            RData::CNAME(ref name) => format!("CNAME: {}", name),
            RData::MX(ref mx) => {
                format!("MX: {} with preference {}", mx.exchange(), mx.preference())
            }
            RData::NS(ref name) => format!("NS: {}", name),
            RData::SOA(ref soa) => {
                format!(
                    "SOA: {} {} {} {} {} {} {}",
                    soa.mname(),
                    soa.rname(),
                    soa.serial(),
                    soa.refresh(),
                    soa.retry(),
                    soa.expire(),
                    soa.minimum()
                )
            }
            RData::TXT(ref txt) => format!("TXT: {}", txt.txt_data().join(" ")),
            RData::PTR(ref ptr) => format!("PTR: {}", ptr.to_string()),
            ref x => format!(" * unclassified answer: {:?}", x),
        };
        write!(f, "{}", str)
    }
}

fn print_error<T: ChainedError>(err: &T) {
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
    errors {
        CliArgsParsingError {
            description("failed to parse CLI arguments")
            display("failed to parse CLI arguments")
        }

        ResolvConfError {
            description("failed to parse /etc/resolv.conf")
            display("failed to parse /etc/resolv.cons")
        }

        ServerIpAddrParsingError {
            description("failed to parse server IP address")
            display("failed to parse server IP address")
        }

        ResoureRecordTypeParsingError {
            description("failed to parse resource record type")
            display("failed to parse resource record type")
        }
    }

    links {
        Lookup(::mhost::lookup::Error, ::mhost::lookup::ErrorKind);
    }
}

quick_main!(run);
