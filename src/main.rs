#![feature(attr_literals)]

#[macro_use]
extern crate error_chain;
extern crate mhost;
extern crate resolv_conf;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;
extern crate tokio_core;
extern crate trust_dns;

use mhost::{multiple_lookup, DnsQuery};

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use structopt::StructOpt;
use tokio_core::reactor::Core;
use trust_dns::rr::{RData, RecordType};

static DEFAULT_RECORD_TYPES: &'static [&str] = &[ "a", "aaaa", "mx" ];

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

#[derive(StructOpt, Debug)]
#[structopt(name = "mhost", about = "Like `host`, but uses multiple DNS servers massively parallel and compares results")]
struct CliArgs {
    /// DNS servers to use; if empty use predefined, public DNS servers
    #[structopt(name = "DNS server", long = "server", short = "s", number_of_values = 1)]
    dns_servers: Vec<String>,

    /// Do not use local (/etc/resolv.conf) nameservers
    #[structopt(name = "don't use local DNS server", short = "L")]
    dont_use_local_dns_servers: bool,

    /// Select resource record type [default: a, aaaa, mx]
    #[structopt(name = "record type", long = "type", short = "t", number_of_values = 1,
        possible_value = "a",
        possible_value = "aaaa",
        possible_value = "any",
        possible_value = "cname",
        possible_value = "dnskey",
        possible_value = "mx",
        possible_value = "ns",
        possible_value = "opt",
        possible_value = "ptr",
        possible_value = "soa",
        possible_value = "srv",
        possible_value = "txt",
    )]
    record_types: Vec<String>,

    /// Timeout for server responses in sec
    #[structopt(name = "time out", long = "timeout", default_value = "5")]
    timeout: u32,

    /// domain name to lookup
    #[structopt(name = "domain name")]
    domain_name: String,
}

// Newtype pattern for Display implementation
struct DnsResponse<'a>(pub &'a mhost::DnsResponse);

// Display impl for plain, basic output
impl<'a> fmt::Display for DnsResponse<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let DnsResponse(dns_response) = *self;
        if dns_response.answers.is_empty() {
            return write!(f, "DNS server {} has not records.", dns_response.server);
        }
        let _ = write!(f, "DNS server {} responded with\n", dns_response.server);
        let mut answers: Vec<String> = dns_response.answers
            .iter()
            .map(|answer| {
                match *answer.rdata() {
                    RData::A(ip)  => format!(" * IPv4: {}", ip),
                    RData::AAAA(ip)  => format!(" * IPv6: {}", ip),
                    RData::CNAME(ref name)  => format!(" * CNAME: {}", name),
                    RData::MX(ref mx)  => format!(" * MX: {} with preference {}", mx.exchange(), mx.preference()),
                    RData::NS(ref name)  => format!(" * NS: {}", name),
                    RData::SOA(ref soa)  => format!(" * SOA: {} {} {} {} {} {} {}",
                        soa.mname(), soa.rname(), soa.serial(), soa.refresh(), soa.retry(), soa.expire(), soa.minimum()),
                    RData::TXT(ref txt)  => format!(" * TXT: {}", txt.txt_data().join(" ")),
                    RData::PTR(ref ptr)  => format!(" * PTR: {}", ptr.to_string()),
                    ref x => format!(" * unclassified answer: {:?}", x)
                }
            })
            .collect();
        answers.sort();
        write!(f, "{}", answers.join("\n"))
    }
}

fn run() -> Result<()> {
    let args = CliArgs::from_args();

    // Check if domain_name is an IP address -> PTR query and ignore -t, else normal query
    let record_types = if let Ok(_) = IpAddr::from_str(&args.domain_name) {
            vec!["PTR"]
                .iter()
                .map(|rt| RecordType::from_str(&rt.to_uppercase()).unwrap())
                .collect()
    } else {
        if !args.record_types.is_empty() {
            args.record_types
                .iter()
                .map(|rt| RecordType::from_str(&rt.to_uppercase()).unwrap())
                .collect()
        } else {
             DEFAULT_RECORD_TYPES
                 .iter()
                 .map(|rt| RecordType::from_str(&rt.to_uppercase()).unwrap())
                 .collect()
        }
    };

    let mut servers: Vec<_> = if !args.dns_servers.is_empty() {
        args.dns_servers
            .iter()
            .map(|server| (IpAddr::from_str(server).unwrap(), 53))
            .collect()
    } else {
        DEFAULT_DNS_SERVERS
            .iter()
            .map(|server| (IpAddr::from_str(server).unwrap(), 53))
            .collect()
    };
    if !args.dont_use_local_dns_servers {
        let mut buf = Vec::with_capacity(4096);
        let mut f = File::open("/etc/resolv.conf").unwrap();
        f.read_to_end(&mut buf).unwrap();
        let cfg = resolv_conf::Config::parse(&buf[..]).unwrap();
        let mut local_servers: Vec<_> = cfg.nameservers
            .into_iter()
            .map(|s| (s, 53))
            .collect();
        servers.append(&mut local_servers);
    }

    // args.timeout: u32 is a workaround for structopt -- cf.
    let timeout = Duration::from_secs(args.timeout as u64);

    // Check if domain_name is an IP address -> PTR query and ignore -t, else normal query
    let mut query = if let Ok(ip) = IpAddr::from_str(&args.domain_name) {
        DnsQuery::from(ip, record_types)
    } else {
        DnsQuery::new(&args.domain_name, record_types)
    };
    query = query.set_timeout(timeout);

    let mut io_loop = Core::new().unwrap();
    let lookup = multiple_lookup(&io_loop.handle(), query, servers);
    let result = io_loop.run(lookup);

    match result {
        Ok(ref responses) => {
            for response in responses {
                match *response {
                    Ok(ref x) => println!("{}", DnsResponse(x)),
                    Err(ref e) => println!("Error: {}", e)
                }
            }
        },
        Err(_) => {
            println!("General Error");
        }
    }

    Ok(())
}

error_chain! {}

quick_main!(run);
