// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! This file is used by the build script. Therefore all functions generating the app command line parser must be included
//! here. It would be nicer to move at least the subcommands to the corresponding modules, but then all logic, all crates
//! etc. used there have to be available for the build script which makes it much more complex.

use std::str::FromStr;

use clap::{crate_name, App, AppSettings, Arg, SubCommand};

pub static SUPPORTED_RECORD_TYPES: &[&str] = &[
    "A", "AAAA", "ANAME", "ANY", "CNAME", "MX", "NULL", "NS", "PTR", "SOA", "SRV", "TXT",
];

pub static SUPPORTED_OUTPUT_FORMATS: &[&str] = &["json", "summary"];

pub fn create_parser() -> App<'static, 'static> {
    App::new(crate_name!())
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .global_setting(AppSettings::DeriveDisplayOrder)
        .global_setting(AppSettings::DisableHelpSubcommand)
        .global_setting(AppSettings::GlobalVersion)
        .global_setting(AppSettings::InferSubcommands)
        .global_setting(AppSettings::UnifiedHelpMessage)
        .arg(
            Arg::with_name("use-system-resolv-opt")
                .long("use-system-resolv-opt")
                .help("Uses options set in /etc/resolv.conf")
                .long_help("Uses options set in /etc/resolv.conf and overrides all corresponding CLI options")
    )
        .arg(
            Arg::with_name("no-system-nameservers")
                .long("no-system-nameservers")
                .requires("system nameservers")
                .help("Ignores nameservers from /etc/resolv.conf"),
        )
        .arg(
            Arg::with_name("no-system-lookups")
                .short("S")
                .long("no-system-lookups")
                .help("Ignores system nameservers for lookups"),
        )
        .arg(
            Arg::with_name("resolv-conf")
                .long("resolv-conf")
                .value_name("FILE")
                .takes_value(true)
                .help("Uses alternative resolv.conf file"),
        )
        .arg(
            Arg::with_name("ndots")
                .long("ndots")
                .value_name("NUMBER")
                .default_value("1")
                .validator(|str| u8::from_str(&str).map(|_| ()).map_err(|_| "invalid number".to_string()))
                .help("Sets number of dots to qualify domain name as FQDN"),
        )
        .arg(
            Arg::with_name("search-domain")
                .long("search-domain")
                .value_name("DOMAIN")
                .help("Sets the search domain to append if HOSTNAME has less than ndots dots"),
        )
        .arg(
            Arg::with_name("system nameservers")
                .long("system-nameserver")
                .value_name("IP ADDR")
                .takes_value(true)
                .multiple(true)
                .number_of_values(1)
                .help("Adds system nameserver for system lookups; only IP addresses allowed"),
        )
        .arg(
            Arg::with_name("nameservers")
                .short("s")
                .long("nameserver")
                .value_name("HOSTNAME | IP ADDR")
                .takes_value(true)
                .multiple(true)
                .number_of_values(1)
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
            Arg::with_name("predefined")
                .short("p")
                .long("predefined")
                .help("Adds predefined nameservers for lookups"),
        )
        .arg(
            Arg::with_name("predefined-filter")
                .long("predefined-filter")
                .value_name("PROTOCOL")
                .multiple(true)
                .use_delimiter(true)
                .require_delimiter(true)
                .default_value("udp")
                .possible_values(&["udp", "tcp", "https", "tls"])
                .default_value_if("predefined", None, "udp")
                .help("Filters predefined nameservers by protocol"),
        )
        .arg(
            Arg::with_name("list-predefined")
                .long("list-predefined")
                .help("Lists all predefined nameservers"),
        )
        .arg(
            Arg::with_name("nameservers-from-file")
                .short("f")
                .long("nameservers-from-file")
                .value_name("FILE")
                .takes_value(true)
                .help("Adds nameservers from file"),
        )
        .arg(
            Arg::with_name("limit")
                .long("limit")
                .value_name("NUMBER")
                .default_value("100")
                .validator(|str| {
                    usize::from_str(&str)
                        .map(|_| ())
                        .map_err(|_| "invalid number".to_string())
                })
                .help("Sets max. number of nameservers to query"),
        )
        .arg(
            Arg::with_name("max-concurrent-servers")
                .long("max-concurrent-servers")
                .value_name("NUMBER")
                .default_value("10")
                .validator(|str| {
                    usize::from_str(&str)
                        .map(|_| ())
                        .map_err(|_| "invalid number".to_string())
                })
                .help("Sets max. concurrent nameservers"),
        )
        .arg(
            Arg::with_name("max-concurrent-requests")
                .long("max-concurrent-requests")
                .value_name("NUMBER")
                .default_value("5")
                .validator(|str| {
                    usize::from_str(&str)
                        .map(|_| ())
                        .map_err(|_| "invalid number".to_string())
                })
                .help("Sets max. concurrent requests per nameserver"),
        )
        .arg(
            Arg::with_name("retries")
                .long("retries")
                .value_name("NUMBER")
                .default_value("0")
                .validator(|str| {
                    usize::from_str(&str)
                        .map(|_| ())
                        .map_err(|_| "invalid number".to_string())
                })
                .help("Sets number of retries if first lookup to nameserver fails"),
        )
        .arg(
            Arg::with_name("timeout")
                .long("timeout")
                .value_name("TIMEOUT")
                .default_value("5")
                .validator(|str| {
                    u64::from_str(&str)
                        .map(|_| ())
                        .map_err(|_| "invalid number".to_string())
                })
                .help("Sets timeout in seconds for responses"),
        )
        .arg(
            Arg::with_name("resolvers-mode")
                .short("m")
                .long("resolvers-mode")
                .value_name("MODE")
                .default_value("multi")
                .possible_values(&["multi", "uni"])
                .help("Sets resolvers lookup mode")
                .long_help(r#"Sets resolvers mode
* multi: Each query is sent to all available name servers
* uni: Each query is send to exactly on name server
"#
    )
        )
        .arg(
            Arg::with_name("wait-multiple-responses")
                .long("wait-multiple-responses")
                .help("Waits until timeout for additional responses from nameservers"),
        )
        .arg(
            Arg::with_name("no-abort-on-error")
                .long("no-abort-on-error")
                .help("Sets do-not-ignore errors from nameservers"),
        )
        .arg(
            Arg::with_name("no-abort-on-timeout")
                .long("no-abort-on-timeout")
                .help("Sets do-not-ignore timeouts from nameservers"),
        )
        .arg(
            Arg::with_name("no-aborts")
                .long("no-aborts")
                .help("Sets do-not-ignore errors and timeouts from nameservers"),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .value_name("FORMAT")
                .takes_value(true)
                .default_value("summary")
                .possible_values(SUPPORTED_OUTPUT_FORMATS)
                .help("Sets the output format for result presentation"),
        )
        .arg(
            Arg::with_name("output-options")
                .long("output-options")
                .value_name("OPTIONS")
                .multiple(true)
                .use_delimiter(true)
                .require_delimiter(true)
                .default_value_if("output", Some("json"), "pretty")
                .default_value_if("output", Some("summary"), "human")
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
            Arg::with_name("show-errors")
                .long("show-errors")
                .conflicts_with("quiet")
                .help("Shows error counts"),
        )
        .arg(
            Arg::with_name("quiet")
                .short("q")
                .long("quiet")
                .help("Does not print anything but results"),
        )
        // This is a special option that is not reflected in GlobalConfig, but is checked during
        // setup in `mhost.rs`.
        .arg(
            Arg::with_name("no-color")
                .long("no-color")
                .help("Disables colorful output"),
        )
        // This is a special option that is not reflected in GlobalConfig, but is checked during
        // setup in `mhost.rs` and set the global AtomicBool `mhost::output::styles::ASCII_MODE`.
        .arg(
            Arg::with_name("ascii")
                .long("ascii")
                .help("Uses only ASCII compatible characters for output"),
        )
        // This is a special option that is not reflected in GlobalConfig, but is checked during
        // setup in `mhost.rs`.
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity"),
        )
        // This is a special option that is not reflected in GlobalConfig, but is checked during
        // setup in `mhost.rs`.
        .arg(
            Arg::with_name("debug")
                .long("debug")
                .help("Uses debug formatting for logging -- much more verbose"),
        )
        // This is a hidden parameter for debugging and experimentation only
        .arg(
            Arg::with_name("max-worker-threads")
                .long("max-worker-threads")
                .value_name("NUMBER")
                .validator(|str| {
                    usize::from_str(&str)
                        .map(|_| ())
                        .map_err(|_| "invalid number".to_string())
                })
                .hidden(true)
                .help("Set the max. number of worker threads overriding derived value")
        )
        .subcommands(subcommands())
}

fn subcommands() -> Vec<App<'static, 'static>> {
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

fn check_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("check")
        .about("Checks all available records for known misconfigurations or mistakes")
        .arg(
            Arg::with_name("domain name")
                .index(1)
                .required(true)
                .value_name("DOMAIN NAME")
                .next_line_help(false)
                .help("domain name to check")
                .long_help("* DOMAIN NAME may be any valid DNS name, e.g., lukas.pustina.de"),
        )
        .arg(
            Arg::with_name("partial-results")
                .short("p")
                .long("show-partial-results")
                .help("Shows results after each check step"),
        )
        .arg(
            Arg::with_name("show-intermediate-lookups")
                .short("i")
                .long("show-intermediate-lookups")
                .requires("partial-results")
                .help("Shows all lookups made during by all checks"),
        )
        .arg(
            Arg::with_name("no-cnames")
                .long("no-cnames")
                .help("Does not run cname lints"),
        )
        .arg(Arg::with_name("no-soa").long("no-soa").help("Does not run SOA check"))
        .arg(Arg::with_name("no-spf").long("no-spf").help("Does not run SPF check"))
}

fn discover_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("discover")
        .about("Discovers records of a domain using multiple heuristics")
        .arg(
            Arg::with_name("domain name")
                .required(true)
                .index(1)
                .value_name("DOMAIN NAME")
                .next_line_help(false)
                .help("domain name to discover")
                .long_help("* DOMAIN NAME may be any valid DNS name, e.g., lukas.pustina.de"),
        )
        .arg(
            Arg::with_name("partial-results")
                .short("p")
                .long("show-partial-results")
                .help("Shows results after each lookup step"),
        )
        .arg(
            Arg::with_name("wordlist-from-file")
                .short("w")
                .long("wordlist-from-file")
                .value_name("FILE")
                .takes_value(true)
                .help("Uses wordlist from file"),
        )
        .arg(
            Arg::with_name("rnd-names-number")
                .long("rnd-names-number")
                .value_name("NUMBER")
                .default_value("3")
                .validator(|str| {
                    u64::from_str(&str)
                        .map(|_| ())
                        .map_err(|_| "invalid number".to_string())
                })
                .help("Sets number of random domain names to generate for wildcard resolution check"),
        )
        .arg(
            Arg::with_name("rnd-names-len")
                .long("rnd-names-len")
                .value_name("LEN")
                .default_value("32")
                .validator(|str| {
                    u64::from_str(&str)
                        .map(|_| ())
                        .map_err(|_| "invalid number".to_string())
                })
                .help("Sets length of random domain names to generate for wildcard resolution check"),
        )
        .arg(
            Arg::with_name("subdomains-only")
                .short("s")
                .long("subdomains-only")
                .help("Shows subdomains only omitting all other discovered names"),
        )
}

fn lookup_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("lookup")
        .about("Looks up a name, IP address or CIDR block")
        .arg(
            Arg::with_name("domain name")
                .required_unless("list-predefined")
                .index(1)
                .value_name("DOMAIN NAME | IP ADDR | CIDR BLOCK [| SERVICE SPEC]")
                .next_line_help(false)
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
            Arg::with_name("record-types")
                .short("t")
                .long("record-type")
                .value_name("RECORD TYPE")
                .takes_value(true)
                .multiple(true)
                .use_delimiter(true)
                .require_delimiter(true)
                .default_value("A,AAAA,CNAME,MX")
                .default_value_if("parse-as-service", None, "SRV")
                .possible_values(SUPPORTED_RECORD_TYPES)
                .help("Sets record type to lookup, will be ignored in case of IP address lookup"),
        )
        .arg(
            Arg::with_name("all-record-types")
                .long("all")
                .alias("xmas")
                .help("Enables lookups for all record types"),
        )
        .arg(
            Arg::with_name("parse-as-service")
                .short("s")
                .long("service")
                .conflicts_with("all-record-types")
                .overrides_with("record-types")
                .help("Parses ARG as service spec and set record type to SRV"),
        )
        .arg(
            Arg::with_name("whois")
                .short("w")
                .long("whois")
                .help("Retrieves Whois information about A, AAAA, and PTR records"),
        )
}

fn server_lists_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("server-lists")
        .about("Downloads known lists of name servers")
        .arg(
            Arg::with_name("server_list_spec")
                .index(1)
                .value_name("SERVER LIST SPEC")
                .multiple(true)
                .required(true)
                .next_line_help(false)
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
            Arg::with_name("output-file")
                .short("o")
                .long("output-file")
                .required(true)
                .value_name("FILE")
                .takes_value(true)
                .help("Sets path to output file"),
        )
}

pub fn show_help() {
    let _ = create_parser().print_help();
    // Force line break; otherwise the shell prompt starts at last line of help.
    println!();
}
