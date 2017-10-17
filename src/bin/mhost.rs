#[macro_use]
extern crate clap;
#[macro_use]
extern crate error_chain;
extern crate futures;
extern crate mhost;
extern crate tokio_core;
extern crate trust_dns;

use mhost::{Query, Response, multiple_lookup};
use mhost::lookup::{self, Result as LookupResult};
use mhost::get;
use mhost::output::{self, OutputModule};

use clap::{App, Arg, ArgMatches, Shell};
use futures::Future;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio_core::reactor::Core;
use trust_dns::rr::RecordType;

fn run() -> Result<()> {
    let args = build_cli().get_matches();

    if args.is_present("completions") {
        return generate_completion(&args);
    }

    let (query, server_limit) = parse_args(&args)?;
    let responses = run_lookup(&args, query, server_limit);
    output(&responses, args.values_of_lossy("output modules").unwrap());
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
            Arg::with_name("ungefiltert ids")
                .short("u")
                .takes_value(true)
                .multiple(true)
                .require_delimiter(true)
                .help("Retrieves DNS servers from https://www.ungefiltert-surfen.de/ for country ids, e.g., 'de'")
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

fn parse_args(args: &ArgMatches) -> Result<(Query, usize)> {
    let timeout = value_t!(args, "timeout", u64)
        .map(Duration::from_secs)
        .unwrap();

    let query = match IpAddr::from_str(args.value_of("domain name").unwrap()) {
        Ok(ip) => Query::from(ip, vec![RecordType::PTR]),
        Err(_) => {
            let record_types = get::record_types(args.values_of_lossy("record types"))
                .chain_err(|| {
                    ErrorKind::CliArgsParsingError
                })?;
            Query::new(args.value_of("domain name").unwrap(), record_types)
        }
    }.set_timeout(timeout);

    let server_limit = value_t!(args, "limit", usize).unwrap();

    Ok((query, server_limit))
}

// TODO: make this a Result
fn run_lookup(args: &ArgMatches, query: Query, server_limit: usize) -> Vec<LookupResult<Response>> {
    let mut io_loop = Core::new().unwrap();
    let handle = io_loop.handle();
    let lookup =
        get::dns_servers(
            &handle,
            args.values_of_lossy("DNS servers"),
            args.is_present("predefined server"),
            args.is_present("dont use local dns servers"),
            args.values_of_lossy("ungefiltert ids")
        )
            .map_err(|e| {
                e.into()
            })
            .and_then(|servers| {
                let dns_endpoints = servers
                    .into_iter()
                    .map(|s| (s, 53))
                    .take(server_limit)
                    .collect();
                multiple_lookup(&handle, query, dns_endpoints)
                    .map_err(|_| {
                        Error::from_kind(ErrorKind::LookupFailed)
                    })
            });
    let result = io_loop.run(lookup);

    result.unwrap()
}

fn output(responses: &[LookupResult<Response>], outputs: Vec<String>) -> () {
    for output in outputs {
        match output.as_ref() {
            "details" => output::DetailsOutput::new(responses).output(),
            _ => output::SummaryOutput::new(responses).output(),
        }
    }
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
    }
}

quick_main!(run);
