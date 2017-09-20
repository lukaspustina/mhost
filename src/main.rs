#![feature(attr_literals)]

extern crate difference;
extern crate mhost;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;
extern crate tokio_core;
extern crate trust_dns;

use mhost::{multiple_lookup};

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;
use structopt::StructOpt;
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

#[derive(StructOpt, Debug)]
#[structopt(name = "mhost", about = "Like `host`, but uses multiple DNS servers massively parallel and compares results")]
struct CliArgs {
    /// DNS servers to use; if empty use predefined, public DNS servers
    #[structopt(name = "DNS server", long = "server", short = "s", number_of_values = 1)]
    dns_servers: Vec<String>,

    /// Select resource record type
    #[structopt(name = "record type", long = "type", short = "t", default_value = "a",
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
    record_type: String,

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
                    ref x => format!(" * unclassified answer: {:?}", x)
                }
            })
            .collect();
        answers.sort();
        write!(f, "{}", answers.join("\n"))
    }
}

fn main() {
    let args = CliArgs::from_args();

    let record_type = RecordType::from_str(&args.record_type.to_uppercase()).unwrap();
    let domain_name = args.domain_name;
    let servers = if !args.dns_servers.is_empty() {
        args.dns_servers
            .iter()
            .map(|server| (Ipv4Addr::from_str(server).unwrap(), 53))
            .collect()
    } else {
        DEFAULT_DNS_SERVERS
            .to_vec()
            .iter()
            .map(|server| (Ipv4Addr::from_str(server).unwrap(), 53))
            .collect()
    };

    let mut io_loop = Core::new().unwrap();
    let lookup = multiple_lookup(&io_loop.handle(), &domain_name, servers, record_type);
    let mut results = io_loop.run(lookup).unwrap();

    for result in &results {
        match *result {
            Ok(ref response) => {
                println!("{}", DnsResponse(response))
            }
            Err(ref e) => {
                println!("Error: {}", e)
            }
        }
    }

    if results.len() == 2 {
        let one = format!("{}", DnsResponse(&results.pop().unwrap().unwrap()));
        let two = format!("{}", DnsResponse(&results.pop().unwrap().unwrap()));
        let changeset = difference::Changeset::new(&one, &two, " ");
        println!("{}", changeset);
    }
}
