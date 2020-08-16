use std::convert::TryFrom;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{crate_name, App, AppSettings, Arg, ArgMatches};

use crate::app::modules;
use crate::output::json::JsonOptions;
use crate::output::summary::SummaryOptions;
use crate::output::{OutputConfig, OutputType};
use crate::resolver::ResolverOpts;

pub static SUPPORTED_RECORD_TYPES: &[&str] = &[
    "A", "AAAA", "ANAME", "CNAME", "MX", "NULL", "NS", "PTR", "SOA", "SRV", "TXT",
];

pub static SUPPORTED_OUTPUT_FORMATS: &[&str] = &["json", "summary"];

pub fn setup_clap() -> App<'static, 'static> {
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
                .conflicts_with("domain name")
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
        .subcommands(modules::subcommands())
}

pub struct GlobalConfig {
    pub list_predefined: bool,
    pub max_concurrent_servers: usize,
    pub ignore_system_resolv_opt: bool,
    pub retries: usize,
    pub max_concurrent_requests: usize,
    pub timeout: Duration,
    pub expects_multiple_responses: bool,
    pub abort_on_error: bool,
    pub abort_on_timeout: bool,
    pub resolv_conf_path: String,
    pub show_errors: bool,
    pub quiet: bool,
    pub ignore_system_nameservers: bool,
    pub nameservers: Option<Vec<String>>,
    pub predefined: bool,
    pub predefined_filter: Option<Vec<String>>,
    pub nameserver_file_path: Option<String>,
    pub limit: usize,
    pub system_nameservers: Option<Vec<String>>,
    pub output: OutputType,
    pub output_config: OutputConfig,
}

impl TryFrom<&ArgMatches<'_>> for GlobalConfig {
    type Error = anyhow::Error;

    fn try_from(args: &ArgMatches) -> std::result::Result<Self, Self::Error> {
        let output = args
            .value_of("output")
            .map(|x| OutputType::try_from(x).context("failed to parse output type"))
            .unwrap()?; // Safe unwrap, because of clap's validation
        let config = GlobalConfig {
            list_predefined: args.is_present("list-predefined"),
            max_concurrent_servers: args
                .value_of("max-concurrent-servers")
                .map(|x| usize::from_str(x).context("failed to parse max-concurrent-servers"))
                .unwrap()?, // Safe unwrap, because clap's validation
            ignore_system_resolv_opt: args.is_present("no-system-resolv-opt"),
            retries: args
                .value_of("retries")
                .map(|x| usize::from_str(x).context("failed to parse retries"))
                .unwrap()?, // Safe unwrap, because clap's validation
            max_concurrent_requests: args
                .value_of("max-concurrent-requests")
                .map(|x| usize::from_str(x).context("max-concurrent-requests"))
                .unwrap()?, // Safe unwrap, because clap's validation
            timeout: args
                .value_of("timeout")
                .map(|x| {
                    u64::from_str(x)
                        .map(Duration::from_secs)
                        .context("failed to parse timeout")
                })
                .unwrap()?, // Safe unwrap, because clap's validation
            expects_multiple_responses: args.is_present("wait-multiple-responses"),
            abort_on_error: !(args.is_present("no-abort-on-error") || args.is_present("no-aborts")),
            abort_on_timeout: !(args.is_present("no-abort-on-timeout") || args.is_present("no-aborts")),
            resolv_conf_path: args.value_of("resolv-conf").unwrap_or("/etc/resolv.conf").to_string(),
            show_errors: args.is_present("show-errors"),
            quiet: args.is_present("quiet"),
            ignore_system_nameservers: args.is_present("no-system-nameservers"),
            nameservers: args
                .values_of("nameservers")
                .map(|xs| xs.map(ToString::to_string).collect()),
            predefined: args.is_present("predefined"),
            predefined_filter: args
                .values_of("predefined-filter")
                .map(|xs| xs.map(ToString::to_string).collect()),
            nameserver_file_path: args.value_of("nameservers-from-file").map(ToString::to_string),
            limit: args
                .value_of("limit")
                .map(|x| usize::from_str(x).context("failed to parse limit"))
                .unwrap()?, // Safe unwrap, because clap's validation
            system_nameservers: args
                .values_of("system nameservers")
                .map(|xs| xs.map(ToString::to_string).collect()),
            output_config: output_config(output, &args)?,
            output,
        };

        Ok(config)
    }
}

impl GlobalConfig {
    pub fn resolver_opts(&self, default_opts: ResolverOpts) -> ResolverOpts {
        ResolverOpts {
            retries: self.retries,
            max_concurrent_requests: self.max_concurrent_requests,
            timeout: self.timeout,
            expects_multiple_responses: self.expects_multiple_responses,
            abort_on_error: self.abort_on_error,
            abort_on_timeout: self.abort_on_timeout,
            ..default_opts
        }
    }
}

pub fn show_help() {
    let _ = setup_clap().print_help();
    println!();
}

fn output_config(output_type: OutputType, args: &ArgMatches<'_>) -> Result<OutputConfig> {
    let args = args
        .values_of("output-options")
        .context("No output options specified")?;
    parse_output_options(output_type, args)
}

fn parse_output_options<'a, I: Iterator<Item = &'a str>>(output_type: OutputType, options: I) -> Result<OutputConfig> {
    let options: Vec<&str> = options.collect();
    match output_type {
        OutputType::Json => {
            let options = JsonOptions::try_from(options).context("failed to parse json options")?;
            Ok(OutputConfig::json(options))
        }
        OutputType::Summary => {
            let options = SummaryOptions::try_from(options).context("failed to parse json options")?;
            Ok(OutputConfig::summary(options))
        }
    }
}
