use std::str::FromStr;
use std::time::Duration;

use clap::{App, AppSettings, Arg};

use crate::app::{SUPPORTED_OUTPUT_FORMATS, SUPPORTED_RECORD_TYPES};
use crate::estimate::Estimate;
use crate::nameserver::predefined;
use crate::resolver::{Lookups, MultiQuery, ResolverGroup, ResolverGroupOpts, ResolverOpts};
use crate::statistics::Statistics;

pub fn setup_clap() -> App<'static, 'static> {
    App::new("mhost")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .setting(AppSettings::DisableHelpSubcommand)
        .setting(AppSettings::DeriveDisplayOrder)
        .setting(AppSettings::UnifiedHelpMessage)
        .setting(AppSettings::VersionlessSubcommands)
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
        .arg(Arg::with_name("no-system-resolv-opt")
            .long("no-system-resolv-opt")
            .help("Ignores options set in /etc/resolv.conf")
        )
        .arg(Arg::with_name("no-system-nameservers")
            .long("no-system-nameservers")
            .requires("system nameservers")
            .help("Ignores nameservers from /etc/resolv.conf")
        )
        .arg(Arg::with_name("resolv-conf")
            .long("resolv-conf")
            .value_name("FILE")
            .takes_value(true)
            .help("Uses alternative resolv.conf file")
        )
        .arg(Arg::with_name("system nameservers")
            .short("S")
            .long("system-nameserver")
            .value_name("IP ADDR")
            .takes_value(true)
            .multiple(true)
            .help("Adds system nameserver for system lookups; only IP addresses allowed")
        )
        .arg(Arg::with_name("nameservers")
            .short("s")
            .long("nameserver")
            .value_name("HOSTNAME | IP ADDR")
            .takes_value(true)
            .multiple(true)
            .use_delimiter(true)
            .require_delimiter(true)
            .value_delimiter(";")
            .help("Adds nameserver for lookups")
        )
        .arg(Arg::with_name("predefined")
            .short("p")
            .long("predefined")
            .help("Adds predefined nameservers for lookups")
        )
        .arg(Arg::with_name("predefined-filter")
            .long("predefined-filter")
            .value_name("PROTOCOL")
            .multiple(true)
            .use_delimiter(true)
            .require_delimiter(true)
            .default_value("udp,tcp,https,tls")
            .possible_values(&["udp", "tcp", "https", "tls"])
            .default_value_if("predefined", None, "udp,tcp,https,tls")
            .help("Filters predefined nameservers by protocol")
        )
        .arg(Arg::with_name("list-predefined")
            .long("list-predefined")
            .conflicts_with("domain name")
            .help("Lists all predefined nameservers")
        )
        .arg(Arg::with_name("nameservers-from-file")
            .short("f")
            .long("nameservers-from-file")
            .value_name("FILE")
            .takes_value(true)
            .help("Adds nameserver for lookups from file")
        )
        .arg(Arg::with_name("limit")
            .long("limit")
            .value_name("NUMBER")
            .default_value("100")
            .validator(|str| usize::from_str(&str).map(|_| ()).map_err(|_| "invalid number".to_string()))
            .help("Sets max. numnber of nameservers to query")
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
        .arg(Arg::with_name("randomized-lookup")
            .short("R")
            .long("randomized-lookup")
            .help("Switches into randomize lookup mode: every query will be send just once to a one randomly chosen nameserver. This can be used to distribute queries among the available nameservers.")
        )
        .arg(Arg::with_name("max-concurrent-servers")
            .long("max-concurrent-servers")
            .value_name("NUMBER")
            .default_value("10")
            .validator(|str| usize::from_str(&str).map(|_| ()).map_err(|_| "invalid number".to_string()))
            .help("Sets max. concurrent nameservers")
        )
        .arg(Arg::with_name("max-concurrent-requests")
            .long("max-concurrent-requests")
            .value_name("NUMBER")
            .default_value("5")
            .validator(|str| usize::from_str(&str).map(|_| ()).map_err(|_| "invalid number".to_string()))
            .help("Sets max. concurrent requests per nameserver")
        )
        .arg(Arg::with_name("attempts")
            .long("attempts")
            .value_name("ATTEMPTS")
            .default_value("1")
            .validator(|str| usize::from_str(&str).map(|_| ()).map_err(|_| "invalid number".to_string()))
            .help("Sets number of attempts to get response in case of timeout or error")
        )
        .arg(Arg::with_name("timeout")
            .long("timeout")
            .value_name("TIMEOUT")
            .default_value("5")
            .validator(|str| u64::from_str(&str).map(|_| ()).map_err(|_| "invalid number".to_string()))
            .help("Sets timeout in seconds for responses")
        )
        .arg(Arg::with_name("wait-multiple-responses")
            .long("wait-multiple-responses")
            .help("Waits until timeout for additional responses from nameservers")
        )
        .arg(Arg::with_name("no-abort-on-error")
            .long("no-abort-on-error")
            .help("Sets do-not-ignore errors from nameservers")
        )
        .arg(Arg::with_name("no-abort-on-timeout")
            .long("no-abort-on-timeout")
            .help("Sets do-not-ignore timeouts from nameservers")
        )
        .arg(Arg::with_name("no-aborts")
            .long("no-aborts")
            .help("Sets do-not-ignore errors and timeouts from nameservers")
        )
        .arg(Arg::with_name("output")
            .short("o")
            .long("output")
            .value_name("FORMAT")
            .takes_value(true)
            .default_value("summary")
            .possible_values(SUPPORTED_OUTPUT_FORMATS)
            .help("Sets the output format for result presentation")
        )
        .arg(Arg::with_name("output-options")
            .long("output-options")
            .value_name("OPTIONS")
            .multiple(true)
            .use_delimiter(true)
            .require_delimiter(true)
            .default_value_if("output", Some("json"), "pretty")
            .default_value_if("output", Some("summary"), "human")
            .help("Sets output options")
            .long_help("* Json: 'pretty': Prettifies output
* Summary: 'human': Uses human readable formatting, 'condensed': Simplifies output")
        )
        .arg(Arg::with_name("quiet")
            .short("q")
            .long("quiet")
            .help("Does not print anything but results")
        )
        .arg(Arg::with_name("no-color")
            .long("no-color")
            .help("Disables colorful output")
        )
        .arg(Arg::with_name("v")
            .short("v")
            .multiple(true)
            .help("Sets the level of verbosity"))
}

pub fn list_predefined_nameservers() {
    println!("List of predefined servers:");
    for ns in predefined::nameserver_configs() {
        println!("* {}", ns);
    }
}

pub fn print_opts(group_opts: &ResolverGroupOpts, opts: &ResolverOpts) {
    println!(
        "Nameservers options: concurrent nameservers={}, max. nameservers={}, concurrent requests={}, attempts={}, timeout={} s{}{}{}",
        group_opts.max_concurrent,
        group_opts.limit.unwrap(), // Safe unwrap, because of Clap's default value
        opts.max_concurrent_requests,
        opts.attempts,
        opts.timeout.as_secs(),
        if opts.expects_multiple_responses {
            ", wait for additional responses"
        } else {
            ""
        },
        if opts.abort_on_error { ", abort on error" } else { "" },
        if opts.abort_on_timeout {
            ", abort on timeout"
        } else {
            ""
        },
    )
}

pub fn print_estimates(resolvers: &ResolverGroup, query: &MultiQuery) {
    let num_servers = resolvers.opts.limit.unwrap().min(resolvers.len()); // Safe unwrap, because of Clap's default value
    let num_names = query.num_names();
    let num_record_types = query.num_record_types();
    let estimate = resolvers.estimate(query);

    let queries_str = if estimate.min_requests == estimate.max_requests {
        format!(
            "{} {}",
            estimate.min_requests,
            if estimate.min_requests > 1 {
                "requests"
            } else {
                "request"
            }
        )
    } else {
        format!(
            "between {} and {} requests",
            estimate.min_requests, estimate.max_requests
        )
    };
    let namesservers_str = if num_servers > 1 {
        format!("{} nameservers", num_servers)
    } else {
        "1 nameserver".to_string()
    };
    let record_types_str = if num_record_types > 1 {
        format!("{} record types", num_record_types)
    } else {
        "1 record type".to_string()
    };
    let names_str = if num_names > 1 {
        format!("{} record types", num_names)
    } else {
        "1 name".to_string()
    };

    println!(
        "Sending {} to {} for {} of {}.",
        queries_str, namesservers_str, record_types_str, names_str
    )
}

pub fn print_statistics(lookups: &Lookups, total_run_time: Duration) {
    let statistics = lookups.statistics();
    println!(
        "Received {} within {} ms of total run time.",
        statistics,
        total_run_time.as_millis()
    );
}
