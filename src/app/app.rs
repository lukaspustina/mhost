use std::str::FromStr;

use clap::{crate_name, App, AppSettings, Arg, SubCommand};

pub static SUPPORTED_RECORD_TYPES: &[&str] = &[
    "A", "AAAA", "ANAME", "CNAME", "MX", "NULL", "NS", "PTR", "SOA", "SRV", "TXT",
];

pub static SUPPORTED_OUTPUT_FORMATS: &[&str] = &["json", "summary"];

pub fn app() -> App<'static, 'static> {
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
            Arg::with_name("no-system-resolv-opt")
                .long("no-system-resolv-opt")
                .help("Ignores options set in /etc/resolv.conf"),
        )
        .arg(
            Arg::with_name("no-system-nameservers")
                .long("no-system-nameservers")
                .requires("system nameservers")
                .help("Ignores nameservers from /etc/resolv.conf"),
        )
        .arg(
            Arg::with_name("resolv-conf")
                .long("resolv-conf")
                .value_name("FILE")
                .takes_value(true)
                .help("Uses alternative resolv.conf file"),
        )
        .arg(
            Arg::with_name("system nameservers")
                .short("S")
                .long("system-nameserver")
                .value_name("IP ADDR")
                .takes_value(true)
                .multiple(true)
                .help("Adds system nameserver for system lookups; only IP addresses allowed"),
        )
        .arg(
            Arg::with_name("nameservers")
                .short("s")
                .long("nameserver")
                .value_name("HOSTNAME | IP ADDR")
                .takes_value(true)
                .multiple(true)
                .use_delimiter(true)
                .require_delimiter(true)
                .value_delimiter(";")
                .help("Adds nameserver for lookups"),
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
                .default_value("udp,tcp,https,tls")
                .possible_values(&["udp", "tcp", "https", "tls"])
                .default_value_if("predefined", None, "udp,tcp,https,tls")
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
                .help("Adds nameserver for lookups from file"),
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
                .value_name("RETRIES")
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
                    "* Json: 'pretty': Prettifies output
* Summary: 'human': Uses human readable formatting, 'condensed': Simplifies output",
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
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity"),
        )
        .subcommands(subcommands())
}

fn subcommands() -> Vec<App<'static, 'static>> {
    vec![
        discover_subcommand(),
        get_server_lists_subcommand(),
        lookup_subcommand(),
        soa_check_subcommand(),
    ]
    .into_iter()
    .map(|x| x.version(env!("CARGO_PKG_VERSION")).author(env!("CARGO_PKG_AUTHORS")))
    .collect()
}

fn discover_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("discover")
        .about("Discovers records of a domain using multiple heuristics")
        .arg(
            Arg::with_name("domain name")
                .index(1)
                .value_name("NAME")
                .next_line_help(false)
                .help("domain name to check")
                .long_help("* DOMAIN NAME may be any valid DNS name, e.g., lukas.pustina.de"),
        )
        .arg(
            Arg::with_name("partial-results")
                .short("p")
                .long("show-partial-results")
                .help("Shows results after each lookup step"),
        )
        .arg(
            Arg::with_name("single-server-lookup")
                .short("S")
                .long("single-server-lookup")
                .help("Switches into single server lookup mode: every query will be send just one randomly chosen nameserver. This can be used to distribute queries among the available nameservers.")
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
                .help("Sets number of random domain names to generate for wildcard resolution check")
        )
        .arg(
            Arg::with_name("rnd-names-len")
                .long("rnd-names-len")
                .value_name("len")
                .default_value("32")
                .validator(|str| {
                    u64::from_str(&str)
                        .map(|_| ())
                        .map_err(|_| "invalid number".to_string())
                })
                .help("Sets length of random domain names to generate for wildcard resolution check")
        )
}

fn get_server_lists_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("get-server-lists")
        .about("Downloads known lists of name servers")
        .arg(
            Arg::with_name("server_list_spec")
                .index(1)
                .value_name("SERVER_LIST_SPEC")
                .multiple(true)
                .required(true)
                .next_line_help(false)
                .help("server list specification")
                .long_help(
                    r#"SERVER LIST SPEC as <SOURCE>[:OPTIONS,...]
* 'public-dns' with options - cf. https://public-dns.info
   Example: public-dns:de
  '<top level country domain>': options select servers from that country
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

fn lookup_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("lookup")
        .about("Looks up a name, IP address or CIDR block")
        .arg(Arg::with_name("domain name")
            .required_unless("list-predefined")
            .index(1)
            .value_name("NAME | IP ADDR | CIDR BLOCK")
            .next_line_help(false)
            .help("domain name, IP address, or CIDR block to lookup")
            .long_help(
                "* DOMAIN NAME may be any valid DNS name, e.g., lukas.pustina.de
* IP ADDR may be any valid IPv4 or IPv4 address, e.g., 192.168.0.1
* CIDR BLOCK may be any valid IPv4 or IPv6 subnet in CIDR notation, e.g., 192.168.0.1/24
  all valid IP addresses of a CIDR block will be queried for a reverse lookup")
        )
        .arg(Arg::with_name("record types")
            .short("t")
            .long("record-type")
            .value_name("RECORD TYPE")
            .takes_value(true)
            .multiple(true)
            .use_delimiter(true)
            .require_delimiter(true)
            .default_value("A,AAAA,MX")
            .possible_values(SUPPORTED_RECORD_TYPES)
            .help("Sets record type to lookup, will be ignored in case of IP address lookup")
        )
        .arg(Arg::with_name("all-record-types")
            .long("all")
            .alias("xmas")
            .help("Enables lookups for all record types")
        )
        .arg(Arg::with_name("single-server-lookup")
            .short("S")
            .long("single-server-lookup")
            .help("Switches into single server lookup mode: every query will be send just one randomly chosen nameserver. This can be used to distribute queries among the available nameservers.")
        )
        .arg(Arg::with_name("whois")
            .short("w")
            .long("whois")
            .help("Retrieves Whois information about A, AAAA, and PTR records.")
        )
}

fn soa_check_subcommand() -> App<'static, 'static> {
    SubCommand::with_name("soa-check")
        .about("Checks SOA records of authoritative name servers for deviations")
        .arg(
            Arg::with_name("domain name")
                .index(1)
                .value_name("NAME")
                .next_line_help(false)
                .help("domain name to check")
                .long_help("* DOMAIN NAME may be any valid DNS name, e.g., lukas.pustina.de"),
        )
        .arg(
            Arg::with_name("partial-results")
                .short("p")
                .long("show-partial-results")
                .help("Shows results after each lookup step"),
        )
}
