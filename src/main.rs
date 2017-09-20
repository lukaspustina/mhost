#![feature(attr_literals)]

extern crate mhost;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;
extern crate tokio_core;

use mhost::multiple_lookup;

use std::net::Ipv4Addr;
use std::str::FromStr;
use structopt::StructOpt;
use tokio_core::reactor::Core;

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

    /// domain name to lookup
    #[structopt(name = "domain name")]
    domain_name: String,
}

fn main() {
    let args = CliArgs::from_args();

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
    let lookup = multiple_lookup(&io_loop.handle(), &domain_name, servers);
    let results = io_loop.run(lookup);

    eprintln!("results = {:?}", results);
}
