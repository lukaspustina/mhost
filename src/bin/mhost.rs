extern crate ansi_term;
#[macro_use]
extern crate clap;
#[macro_use]
extern crate error_chain;
extern crate flexi_logger;
extern crate futures;
#[macro_use]
extern crate log;
extern crate mhost;
extern crate tokio_core;
extern crate trust_dns;

use mhost::{Query, Response, multiple_lookup};
use mhost::lookup::{self, Result as LookupResult};
use mhost::get;
use mhost::output::{self, OutputConfig, OutputModule};

use ansi_term::Colour;
use clap::{App, Arg, ArgMatches, Shell};
use flexi_logger::{Logger, LogRecord};
use futures::Future;
use log::LogLevel;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio_core::reactor::Core;
use trust_dns::rr::RecordType;

fn run() -> Result<()> {
    let args = build_cli().get_matches();

    init_looger(args.occurrences_of("debug level"))
        .start()
        .unwrap_or_else(|e| { panic!("Logger initialization failed with {}", e) });

    if args.is_present("completions") {
        return generate_completion(&args);
    }

    let (query, server_limit, output_cfg) = parse_args(&args)?;
    let responses = run_lookup(&args, query, server_limit);

    let output_modules = args.values_of_lossy("output modules").unwrap();
    output(output_modules, &output_cfg, &responses)?;

    Ok(())
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
                .value_name("record type")
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
                .help("Ignore local DNS servers from /etc/resolv.conf")
        )
        .arg(
            Arg::with_name("dont use local search domain")
                .short("S")
                .help("Ignore local search domains from /etc/resolv.conf")
        )
        .arg(Arg::with_name("predefined servers").short("p").help(
            "Uses predefined DNS servers set"
        ))
        .arg(
            Arg::with_name("DNS servers")
                .long("server")
                .short("s")
                .takes_value(true)
                .value_name("DNS server")
                .multiple(true)
                .require_delimiter(true)
                .number_of_values(1)
                .help(
                    "Sets DNS servers to use"
                )
        )
        .arg(
            Arg::with_name("ungefiltert ids")
                .short("u")
                .takes_value(true)
                .value_name("country id")
                .multiple(true)
                .require_delimiter(true)
                .help("Retrieves DNS servers from https://public-dns.info for country id, e.g., 'de'")
        )
        .arg(
            Arg::with_name("limit")
                .long("limit")
                .short("l")
                .default_value("100")
                .help("Limits the amount of servers to query")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("output modules")
                .long("module")
                .short("m")
                .takes_value(true)
                .value_name("output module")
                .multiple(true)
                .require_delimiter(true)
                .default_value("summary")
                .possible_values(
                    &[
                        "summary",
                        "details",
                        "json",
                    ],
                )
                .help("Selects output module")
        )
        .arg(
            Arg::with_name("human-readable output")
                .short("h")
                .help("Sets human-readable output")
        )
        .arg(
            Arg::with_name("show unsupported")
                .long("show-unsupported")
                .help("Shows unsupported resource records")
        )
        .arg(
            Arg::with_name("show nxdomain")
                .long("show-nxdomain")
                .help("Shows NXDOMAIN responses")
        )
        .arg(
            Arg::with_name("hide headers")
                .long("hide-headers")
                .help("Hides output headers")
        )
        .arg(
            Arg::with_name("debug level")
                .short("d")
                .multiple(true)
                .help("Sets debug level")
        )
        .arg(
            Arg::with_name("verbosity level")
                .short("v")
                .multiple(true)
                .help("Sets level of verbosity")
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

fn init_looger(verbosity_level: u64) -> Logger {
    fn colour(l: LogLevel) -> Colour {
        match l {
            LogLevel::Error => Colour::Red,
            LogLevel::Warn => Colour::Yellow,
            LogLevel::Info => Colour::Blue,
            _ => Colour::White,
        }
    }

    fn log_format_info(r: &LogRecord) -> String {
        format!("{}", colour(r.level()).paint(
            format!("{}: {}",
                    r.location().module_path(),
                    &r.args()
            )
        ))
    }

    fn log_format_debug(r: &LogRecord) -> String {
        format!("{}", colour(r.level()).paint(
            format!("{}:{}:{}: {}",
                    r.location().module_path(),
                    r.location().file(),
                    r.location().line(),
                    &r.args()
            )
        ))
    }

    let (log_spec, log_format): (String, fn(&LogRecord) -> String) = match std::env::var("RUST_LOG") {
        Ok(spec) => (spec, log_format_debug),
        Err(_) if verbosity_level == 1 => ("mhost=info".to_string(), log_format_info),
        Err(_) if verbosity_level == 2 => ("mhost=debug".to_string(), log_format_debug),
        Err(_) if verbosity_level > 2 => ("mhost=trace".to_string(), log_format_debug),
        Err(_) => ("mhost=warn".to_string(), log_format_info),
    };

    Logger::with_str(&log_spec).format(log_format)
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

fn parse_args(args: &ArgMatches) -> Result<(Query, usize, OutputConfig)> {
    let timeout = value_t!(args, "timeout", u64)
        .map(Duration::from_secs)
        .unwrap();

    let query = match IpAddr::from_str(args.value_of("domain name").unwrap()) {
        Ok(ip) => Query::from(ip, vec![RecordType::PTR]),
        Err(_) => {
            let domain_name = if args.is_present("dont use local search domain") {
                args.value_of("domain name").unwrap().to_string()
            } else {
                let cfg = get::resolv_conf()?;
                let domain_name_from_args = args.value_of("domain name").unwrap();
                if domain_name_from_args.ends_with('.') {
                    domain_name_from_args.to_string()
                } else if !cfg.search.is_empty() && domain_name_from_args.matches('.').count() >= cfg.ndots as usize {
                    format!("{}.", domain_name_from_args)
                } else {
                    format!("{}.{}.", domain_name_from_args, cfg.search.first().unwrap())
                }
            };
            debug!("domain_name: '{}'", domain_name);

            let record_types = get::record_types(args.values_of_lossy("record types"))
                .chain_err(|| ErrorKind::CliArgsParsingError)?;
            Query::new(&domain_name, record_types)
        }
    }.set_timeout(timeout);
    trace!("{:?}", query);

    let server_limit = value_t!(args, "limit", usize).unwrap();

    let output_cfg = OutputConfig {
        human_readable: args.is_present("human-readable output"),
        show_headers: !args.is_present("hide headers"),
        show_nx_domain: args.is_present("show nxdomain"),
        show_unsupported_rr: args.is_present("show unsupported"),
        verbosity: args.occurrences_of("verbosity level"),
    };

    Ok((query, server_limit, output_cfg))
}

// TODO: make this a Result
fn run_lookup(args: &ArgMatches, query: Query, server_limit: usize) -> Vec<LookupResult<Response>> {
    let mut io_loop = Core::new().unwrap();
    let handle = io_loop.handle();
    let lookup = get::dns_servers(
        &handle,
        args.values_of_lossy("DNS servers"),
        args.is_present("predefined servers"),
        args.is_present("dont use local dns servers"),
        args.values_of_lossy("ungefiltert ids"),
    )
        .map_err(|e| e.into())
        .and_then(|servers| {
            debug!("DNS Server set: {:?}", servers);
            let dns_endpoints = servers
                .into_iter()
                .take(server_limit)
                .collect();
            multiple_lookup(&handle, query, dns_endpoints).map_err(
                |_| {
                    Error::from_kind(ErrorKind::LookupFailed)
                },
            )
        });
    let result = io_loop.run(lookup);

    result.unwrap()
}

fn output<'a, 'b>(outputs: Vec<String>, output_cfg: &OutputConfig, responses: &'b [LookupResult<Response>]) -> Result<()> {
    let mut writer = std::io::stdout();
    for output in outputs {
        match output.as_ref() {
            "json" => output::Json::new(responses).output(&mut writer)?,
            "details" => output::DetailsOutput::new(output_cfg, responses).output(&mut writer)?,
            _ => output::SummaryOutput::new(output_cfg, responses).output(&mut writer)?,
        }
    }

    Ok(())
}

error_chain! {
    errors {
        CliArgsParsingError {
            description("failed to parse CLI arguments")
            display("failed to parse CLI arguments")
        }

        LookupFailed {
            description("failed to run lookup")
            display("failed to run lookup")
        }
    }

    links {
        Get(get::Error, get::ErrorKind);
        Lookup(lookup::Error, lookup::ErrorKind);
        Output(output::Error, output::ErrorKind);
    }
}

quick_main!(run);
