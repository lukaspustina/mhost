// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! This file is used by the build script. Therefore all functions generating the app command line parser must be included
//! here. It would be nicer to move at least the subcommands to the corresponding modules, but then all logic, all crates
//! etc. used there have to be available for the build script which makes it much more complex.

use clap::{Arg, ArgAction, Command};

pub static SUPPORTED_RECORD_TYPES: &[&str] = &[
    "A", "AAAA", "ANAME", "ANY", "CAA", "CNAME", "HINFO", "HTTPS", "MX", "NAPTR", "NULL", "NS", "OPENPGPKEY", "PTR",
    "SOA", "SRV", "SSHFP", "SVCB", "TLSA", "TXT",
];

pub static SUPPORTED_OUTPUT_FORMATS: &[&str] = &["json", "summary"];

pub fn create_parser() -> Command {
    Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .disable_help_subcommand(true)
        .infer_subcommands(true)
        .arg(
            Arg::new("use-system-resolv-opt")
                .long("use-system-resolv-opt")
                .action(ArgAction::SetTrue)
                .help("Uses options set in /etc/resolv.conf")
                .long_help("Uses options set in /etc/resolv.conf and overrides all corresponding CLI options"),
        )
        .arg(
            Arg::new("no-system-nameservers")
                .long("no-system-nameservers")
                .action(ArgAction::SetTrue)
                .requires("system nameservers")
                .help("Ignores nameservers from /etc/resolv.conf"),
        )
        .arg(
            Arg::new("no-system-lookups")
                .short('S')
                .long("no-system-lookups")
                .action(ArgAction::SetTrue)
                .help("Ignores system nameservers for lookups"),
        )
        .arg(
            Arg::new("resolv-conf")
                .long("resolv-conf")
                .value_name("FILE")
                .help("Uses alternative resolv.conf file"),
        )
        .arg(
            Arg::new("ndots")
                .long("ndots")
                .value_name("NUMBER")
                .default_value("1")
                .value_parser(str::parse::<u8>)
                .help("Sets number of dots to qualify domain name as FQDN"),
        )
        .arg(
            Arg::new("search-domain")
                .long("search-domain")
                .value_name("DOMAIN")
                .help("Sets the search domain to append if HOSTNAME has less than ndots dots"),
        )
        .arg(
            Arg::new("system nameservers")
                .long("system-nameserver")
                .value_name("IP ADDR")
                .action(ArgAction::Append)
                .help("Adds system nameserver for system lookups; only IP addresses allowed"),
        )
        .arg(
            Arg::new("nameservers")
                .short('s')
                .long("nameserver")
                .value_name("HOSTNAME | IP ADDR")
                .action(ArgAction::Append)
                .help("Adds nameserver for lookups")
                .long_help(
                    r#"Adds nameserver for lookups. A nameserver may be specified by protocol, hostname or IP address, and port number, delimited by coloons, e.g., udp:dns.google:53. Supported protocols are udp,tcp,tls,https.
Additionally, further parameters like 'tls_auth_name' or 'name' may be added separated by commas. 'tls_auth_name' must be set for protocols 'tls' and 'https' if an IP address is given. If protocol or port number are omitted, the defaults udp and 53 are used, respectively.
Examples:
* 127.0.0.1 is udp:127.0.0.1:53
* ::1 is udp:[::1]:53,name=localhost
* tcp:127.0.0.1 is tcp:127.0.0.1:53
* tls:8.8.8.8:853,tls_auth_name=dns.google,name="Google 1"
* https:[2001:4860:4860::8888]:443,tls_auth_name=dns.google,name="Google 1"

"#),
        )
        .arg(
            Arg::new("predefined")
                .short('p')
                .long("predefined")
                .action(ArgAction::SetTrue)
                .help("Adds predefined nameservers for lookups"),
        )
        .arg(
            Arg::new("predefined-filter")
                .long("predefined-filter")
                .value_name("PROTOCOL")
                .action(ArgAction::Append)
                .value_delimiter(',')
                .default_value("udp")
                .value_parser(["udp", "tcp", "https", "tls"])
                .default_value_if("predefined", "true", "udp")
                .help("Filters predefined nameservers by protocol"),
        )
        .arg(
            Arg::new("list-predefined")
                .long("list-predefined")
                .action(ArgAction::SetTrue)
                .help("Lists all predefined nameservers"),
        )
        .arg(
            Arg::new("nameservers-from-file")
                .short('f')
                .long("nameservers-from-file")
                .value_name("FILE")
                .help("Adds nameservers from file"),
        )
        .arg(
            Arg::new("limit")
                .long("limit")
                .value_name("NUMBER")
                .default_value("100")
                .value_parser(str::parse::<usize>)
                .help("Sets max. number of nameservers to query"),
        )
        .arg(
            Arg::new("max-concurrent-servers")
                .long("max-concurrent-servers")
                .value_name("NUMBER")
                .default_value("10")
                .value_parser(str::parse::<usize>)
                .help("Sets max. concurrent nameservers"),
        )
        .arg(
            Arg::new("max-concurrent-requests")
                .long("max-concurrent-requests")
                .value_name("NUMBER")
                .default_value("5")
                .value_parser(str::parse::<usize>)
                .help("Sets max. concurrent requests per nameserver"),
        )
        .arg(
            Arg::new("retries")
                .long("retries")
                .value_name("NUMBER")
                .default_value("0")
                .value_parser(str::parse::<usize>)
                .help("Sets number of retries if first lookup to nameserver fails"),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .value_name("TIMEOUT")
                .default_value("5")
                .value_parser(str::parse::<u64>)
                .help("Sets timeout in seconds for responses"),
        )
        .arg(
            Arg::new("resolvers-mode")
                .short('m')
                .long("resolvers-mode")
                .value_name("MODE")
                .default_value("multi")
                .value_parser(["multi", "uni"])
                .help("Sets resolvers lookup mode")
                .long_help(r#"Sets resolvers mode
* multi: Each query is sent to all available name servers
* uni: Each query is send to exactly on name server
"#
    )
        )
        .arg(
            Arg::new("wait-multiple-responses")
                .long("wait-multiple-responses")
                .action(ArgAction::SetTrue)
                .help("Waits until timeout for additional responses from nameservers"),
        )
        .arg(
            Arg::new("no-abort-on-error")
                .long("no-abort-on-error")
                .action(ArgAction::SetTrue)
                .help("Sets do-not-ignore errors from nameservers"),
        )
        .arg(
            Arg::new("no-abort-on-timeout")
                .long("no-abort-on-timeout")
                .action(ArgAction::SetTrue)
                .help("Sets do-not-ignore timeouts from nameservers"),
        )
        .arg(
            Arg::new("no-aborts")
                .long("no-aborts")
                .action(ArgAction::SetTrue)
                .help("Sets do-not-ignore errors and timeouts from nameservers"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FORMAT")
                .default_value("summary")
                .value_parser(SUPPORTED_OUTPUT_FORMATS.to_vec())
                .help("Sets the output format for result presentation"),
        )
        .arg(
            Arg::new("output-options")
                .long("output-options")
                .value_name("OPTIONS")
                .action(ArgAction::Append)
                .value_delimiter(',')
                .default_value_if("output", "json", "pretty")
                .default_value_if("output", "summary", "human")
                .help("Sets output options")
                .long_help(
                    r#"* Json:
  * 'pretty': Prettifies output
* Summary:
  * 'condensed': Simplifies output,
  * 'human': Uses human readable formatting
  * 'show-domain-names': Shows queried domain names

"#,
                ),
        )
        .arg(
            Arg::new("show-errors")
                .long("show-errors")
                .action(ArgAction::SetTrue)
                .conflicts_with("quiet")
                .help("Shows error counts"),
        )
        .arg(
            Arg::new("quiet")
                .short('q')
                .long("quiet")
                .action(ArgAction::SetTrue)
                .help("Does not print anything but results"),
        )
        // This is a special option that is not reflected in GlobalConfig, but is checked during
        // setup in `mhost.rs`.
        .arg(
            Arg::new("no-color")
                .long("no-color")
                .action(ArgAction::SetTrue)
                .help("Disables colorful output"),
        )
        // This is a special option that is not reflected in GlobalConfig, but is checked during
        // setup in `mhost.rs` and set the global AtomicBool `mhost::output::styles::ASCII_MODE`.
        .arg(
            Arg::new("ascii")
                .long("ascii")
                .action(ArgAction::SetTrue)
                .help("Uses only ASCII compatible characters for output"),
        )
        // This is a special option that is not reflected in GlobalConfig, but is checked during
        // setup in `mhost.rs`.
        .arg(
            Arg::new("v")
                .short('v')
                .action(ArgAction::Count)
                .help("Sets the level of verbosity"),
        )
        // This is a special option that is not reflected in GlobalConfig, but is checked during
        // setup in `mhost.rs`.
        .arg(
            Arg::new("debug")
                .long("debug")
                .action(ArgAction::SetTrue)
                .help("Uses debug formatting for logging -- much more verbose"),
        )
        // This is a hidden parameter for debugging and experimentation only
        .arg(
            Arg::new("max-worker-threads")
                .long("max-worker-threads")
                .value_name("NUMBER")
                .value_parser(str::parse::<usize>)
                .hide(true)
                .help("Set the max. number of worker threads overriding derived value")
        )
        .subcommands(subcommands())
}

fn subcommands() -> Vec<Command> {
    vec![
        check_subcommand(),
        discover_subcommand(),
        lookup_subcommand(),
        server_lists_subcommand(),
    ]
    .into_iter()
    .map(|x| x.version(env!("CARGO_PKG_VERSION")).author(env!("CARGO_PKG_AUTHORS")))
    .collect()
}

fn check_subcommand() -> Command {
    Command::new("check")
        .about("Checks all available records for known misconfigurations or mistakes")
        .arg(
            Arg::new("domain name")
                .index(1)
                .required(true)
                .value_name("DOMAIN NAME")
                .help("domain name to check")
                .long_help("* DOMAIN NAME may be any valid DNS name, e.g., lukas.pustina.de"),
        )
        .arg(
            Arg::new("partial-results")
                .short('p')
                .long("show-partial-results")
                .action(ArgAction::SetTrue)
                .help("Shows results after each check step"),
        )
        .arg(
            Arg::new("show-intermediate-lookups")
                .short('i')
                .long("show-intermediate-lookups")
                .action(ArgAction::SetTrue)
                .requires("partial-results")
                .help("Shows all lookups made during by all checks"),
        )
        .arg(
            Arg::new("no-cnames")
                .long("no-cnames")
                .action(ArgAction::SetTrue)
                .help("Does not run cname lints"),
        )
        .arg(
            Arg::new("no-soa")
                .long("no-soa")
                .action(ArgAction::SetTrue)
                .help("Does not run SOA check"),
        )
        .arg(
            Arg::new("no-spf")
                .long("no-spf")
                .action(ArgAction::SetTrue)
                .help("Does not run SPF check"),
        )
}

fn discover_subcommand() -> Command {
    Command::new("discover")
        .about("Discovers records of a domain using multiple heuristics")
        .arg(
            Arg::new("domain name")
                .required(true)
                .index(1)
                .value_name("DOMAIN NAME")
                .help("domain name to discover")
                .long_help("* DOMAIN NAME may be any valid DNS name, e.g., lukas.pustina.de"),
        )
        .arg(
            Arg::new("partial-results")
                .short('p')
                .long("show-partial-results")
                .action(ArgAction::SetTrue)
                .help("Shows results after each lookup step"),
        )
        .arg(
            Arg::new("wordlist-from-file")
                .short('w')
                .long("wordlist-from-file")
                .value_name("FILE")
                .help("Uses wordlist from file"),
        )
        .arg(
            Arg::new("rnd-names-number")
                .long("rnd-names-number")
                .value_name("NUMBER")
                .default_value("3")
                .value_parser(str::parse::<usize>)
                .help("Sets number of random domain names to generate for wildcard resolution check"),
        )
        .arg(
            Arg::new("rnd-names-len")
                .long("rnd-names-len")
                .value_name("LEN")
                .default_value("32")
                .value_parser(str::parse::<usize>)
                .help("Sets length of random domain names to generate for wildcard resolution check"),
        )
        .arg(
            Arg::new("subdomains-only")
                .short('s')
                .long("subdomains-only")
                .action(ArgAction::SetTrue)
                .help("Shows subdomains only omitting all other discovered names"),
        )
}

fn lookup_subcommand() -> Command {
    Command::new("lookup")
        .about("Looks up a name, IP address or CIDR block")
        .arg(
            Arg::new("domain name")
                .required(true)
                .index(1)
                .value_name("DOMAIN NAME | IP ADDR | CIDR BLOCK [| SERVICE SPEC]")
                .help("domain name, IP address, or CIDR block to lookup")
                .long_help(
                    r#"domain name, IP address, CIDR block, or, if -s, SERVICE SPEC, to lookup"
* DOMAIN NAME may be any valid DNS name, e.g., lukas.pustina.de
* IP ADDR may be any valid IPv4 or IPv4 address, e.g., 192.168.0.1
* CIDR BLOCK may be any valid IPv4 or IPv6 subnet in CIDR notation, e.g., 192.168.0.1/24
  all valid IP addresses of a CIDR block will be queried for a reverse lookup
* SERVICE SPEC may be specified by name, protocol, and domain name, delimited by colons. If protocol is omitted, tcp is assumed, e.g.,
  * dns:udp:example.com is _dns._udp.example.com
  * smtp:tcp:example.com is _smtp._tcp.example.com
  * smtp::example.com is _smtp._tcp.example.com
"#,
                ),
        )
        .arg(
            Arg::new("record-types")
                .short('t')
                .long("record-type")
                .value_name("RECORD TYPE")
                .action(ArgAction::Append)
                .value_delimiter(',')
                .default_value("A,AAAA,CNAME,MX")
                .default_value_if("parse-as-service", "true", "SRV")
                .value_parser(SUPPORTED_RECORD_TYPES.to_vec())
                .help("Sets record type to lookup, will be ignored in case of IP address lookup"),
        )
        .arg(
            Arg::new("all-record-types")
                .long("all")
                .alias("xmas")
                .action(ArgAction::SetTrue)
                .help("Enables lookups for all record types"),
        )
        .arg(
            Arg::new("parse-as-service")
                .short('s')
                .long("service")
                .action(ArgAction::SetTrue)
                .conflicts_with("all-record-types")
                .overrides_with("record-types")
                .help("Parses ARG as service spec and set record type to SRV"),
        )
        .arg(
            Arg::new("whois")
                .short('w')
                .long("whois")
                .action(ArgAction::SetTrue)
                .help("Retrieves Whois information about A, AAAA, and PTR records"),
        )
}

fn server_lists_subcommand() -> Command {
    Command::new("server-lists")
        .about("Downloads known lists of name servers")
        .arg(
            Arg::new("server_list_spec")
                .index(1)
                .value_name("SERVER LIST SPEC")
                .action(ArgAction::Append)
                .required(true)
                .help("server list specification")
                .long_help(
                    r#"SERVER LIST SPEC as <SOURCE>[:OPTIONS,...]
* 'public-dns' with options - cf. https://public-dns.info
  '<top level country domain>': options select servers from that country
   Example: public-dns:de
* 'opennic' with options; uses GeoIP to select servers - cf. https://www.opennic.org
   'anon' - only return servers with anonymized logs only; default is false
   'number=<1..>' - return up to 'number' servers; default is 10
   'reliability=<1..100> - only return server with reliability of 'reliability'% or more; default 95
   'ipv=<4|6|all> - return IPv4, IPv6, or both servers; default all
    Example: opennic:anon,number=10,ipv=4

"#,
                ),
        )
        .arg(
            Arg::new("output-file")
                .short('o')
                .long("output-file")
                .required(true)
                .value_name("FILE")
                .help("Sets path to output file"),
        )
}

pub fn show_help() {
    let _ = create_parser().print_help();
    // Force line break; otherwise the shell prompt starts at last line of help.
    println!();
}
