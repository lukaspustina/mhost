use std::io;
use std::io::Write;
use std::str::FromStr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{App, AppSettings, Arg, ArgMatches};
use futures::future::join_all;
use log::{debug, LevelFilter};
use nom::lib::std::collections::HashSet;

use mhost::estimate::Estimate;
use mhost::nameserver::{predefined, NameServerConfig, NameServerConfigGroup, Protocol};
use mhost::output::summary::SummaryOptions;
use mhost::output::{Output, OutputConfig, OutputFormat};
use mhost::resolver::{Lookups, MultiQuery, ResolverConfigGroup, ResolverGroup, ResolverGroupOpts, ResolverOpts};
use mhost::statistics::Statistics;
use mhost::{IpNetwork, RecordType};

static SUPPORTED_RECORD_TYPES: &[&str] = &[
    "A", "AAAA", "ANAME", "CNAME", "MX", "NULL", "NS", "PTR", "SOA", "SRV", "TXT",
];

#[tokio::main]
async fn main() -> Result<()> {
    let app = setup_clap();
    let args = app.get_matches();

    if args.is_present("no-color") {
        yansi::Paint::disable();
    }
    let log_level = log_level(args.occurrences_of("v"));
    setup_logging(log_level);

    debug!("Parsed args.");
    debug!("Set up logging.");

    run(args).await
}

fn log_level(verbosity: u64) -> LevelFilter {
    match verbosity {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    }
}

fn setup_logging(log_level: LevelFilter) {
    let start = std::time::Instant::now();
    env_logger::Builder::from_default_env()
        .filter_module("mhost", log_level)
        .format(move |buf, rec| {
            let t = start.elapsed().as_secs_f32();
            let thread_id_string = format!("{:?}", std::thread::current().id());
            let thread_id = &thread_id_string[9..thread_id_string.len() - 1];
            writeln!(buf, "{:.03} [{:5}] ({:}) - {}", t, rec.level(), thread_id, rec.args())
        })
        .init();
}

fn setup_clap() -> App<'static, 'static> {
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
            .hidden(true)
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
        .arg(Arg::with_name("attempts")
            .long("attempts")
            .value_name("ATTEMPTS")
            .default_value("2")
            .validator(|str| usize::from_str(&str).map(|_| ()).map_err(|_| "invalid number".to_string()))
            .help("Sets number of attempts to get response in case of timeout or error")
        )
        .arg(Arg::with_name("max-concurrent-requests")
            .long("max-concurrent-requests")
            .value_name("NUMBER")
            .default_value("5")
            .validator(|str| usize::from_str(&str).map(|_| ()).map_err(|_| "invalid number".to_string()))
            .help("Sets max. concurrent requests per nameserver")
        )
        .arg(Arg::with_name("timeout")
            .long("timeout")
            .value_name("TIMEOUT")
            .default_value("5")
            .validator(|str| u64::from_str(&str).map(|_| ()).map_err(|_| "invalid number".to_string()))
            .help("Sets timeout in seconds for responses")
        )
        .arg(Arg::with_name("no-abort-on-error")
            .long("no-abort-on-error")
            .help("Sets do-not-ignore errors from nameservers.")
        )
        .arg(Arg::with_name("no-abort-on-timeout")
            .long("no-abort-on-timeout")
            .help("Sets do-not-ignore timeouts from nameservers.")
        )
        .arg(Arg::with_name("no-aborts")
            .long("no-aborts")
            .help("Sets do-not-ignore errors and timeouts from nameservers.")
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

async fn run(args: ArgMatches<'_>) -> Result<()> {
    if args.is_present("list-predefined") {
        list_predefined_nameservers();
        return Ok(());
    }

    let domain_name = args
        .value_of("domain name")
        .context("No domain name to lookup specified")?;
    let query = build_query(&args, domain_name)?;

    let resolver_group_opts = load_resolver_group_opts(&args)?;
    let resolver_opts = load_resolver_opts(&args)?;
    if !args.is_present("quiet") {
        print_opts(&resolver_group_opts, &resolver_opts);
    }

    let resolvers = create_resolvers(resolver_group_opts, resolver_opts, &args).await?;

    if !args.is_present("quiet") {
        print_estimates(&resolvers, &query);
    }

    let start_time = Instant::now();
    let lookups: Lookups = lookup(&args, query, resolvers).await;
    let total_run_time = Instant::now() - start_time;

    if !args.is_present("quiet") {
        print_statistics(&lookups, total_run_time);
    }

    output(&lookups)
}

fn list_predefined_nameservers() {
    println!("List of predefined servers:");
    for ns in predefined::nameserver_configs() {
        println!("* {}", ns);
    }
}

fn build_query(args: &ArgMatches, domain_name: &str) -> Result<MultiQuery> {
    if let Ok(ip_network) = IpNetwork::from_str(domain_name) {
        ptr_query(ip_network)
    } else {
        let record_types = if args.is_present("all-record-types") {
            SUPPORTED_RECORD_TYPES
                .iter()
                .map(|x| RecordType::from_str(x).unwrap())
                .collect()
        } else {
            let args = args
                .values_of("record types")
                .context("No record types for name lookup specified")?;
            record_types(args)?
        };
        name_query(domain_name, record_types)
    }
}

fn ptr_query(ip_network: IpNetwork) -> Result<MultiQuery> {
    let q = MultiQuery::multi_name(ip_network.iter(), RecordType::PTR).context("Failed to create query")?;
    debug!("Prepared query for reverse lookups.");
    Ok(q)
}

fn record_types<'a, I: Iterator<Item = &'a str>>(record_types: I) -> Result<Vec<RecordType>> {
    let record_types: Vec<_> = record_types
        .map(str::to_uppercase)
        .map(|x| RecordType::from_str(&x))
        .collect();
    let record_types: std::result::Result<Vec<_>, _> = record_types.into_iter().collect();
    record_types.context("Failed to parse record type")
}

fn name_query(name: &str, record_types: Vec<RecordType>) -> Result<MultiQuery> {
    let record_types_len = record_types.len();
    let q = MultiQuery::multi_record(name, record_types).context("Failed to build query")?;
    debug!("Prepared query for name lookup for {} record types.", record_types_len);
    Ok(q)
}

async fn create_resolvers(
    resolver_group_opts: ResolverGroupOpts,
    resolver_opts: ResolverOpts,
    args: &ArgMatches<'_>,
) -> Result<ResolverGroup> {
    let ignore_system_nameservers = args.is_present("no-system-nameservers");

    let system_resolver_group: ResolverConfigGroup = load_system_nameservers(args, ignore_system_nameservers)?.into();
    let mut system_resolvers = ResolverGroup::from_configs(
        system_resolver_group,
        resolver_opts.clone(),
        resolver_group_opts.clone(),
    )
    .await
    .context("Failed to create system resolvers")?;
    debug!("Created {} system resolvers.", system_resolvers.len());

    let resolver_group: ResolverConfigGroup = load_nameservers(args, &mut system_resolvers).await?.into();
    let resolvers = ResolverGroup::from_configs(resolver_group, resolver_opts, resolver_group_opts.clone())
        .await
        .context("Failed to load resolvers")?;
    debug!("Created {} resolvers.", resolvers.len());

    system_resolvers.merge(resolvers);

    Ok(system_resolvers)
}

async fn load_nameservers(
    args: &ArgMatches<'_>,
    system_resolvers: &mut ResolverGroup,
) -> Result<NameServerConfigGroup> {
    let mut nameservers_group = NameServerConfigGroup::new(Vec::new());
    if let Some(configs) = args.values_of("nameservers") {
        let configs: Vec<_> = configs
            .map(|str| NameServerConfig::from_str_with_resolution(&system_resolvers, str))
            .collect();
        let configs: mhost::Result<Vec<_>> = join_all(configs).await.into_iter().collect();
        let nameservers: Vec<_> = configs.context("Failed to parse IP address for system nameserver")?;
        let nameservers = NameServerConfigGroup::new(nameservers);
        debug!("Loaded {} nameservers.", nameservers.len());
        nameservers_group.merge(nameservers);
    }
    if args.is_present("predefined") {
        let filter: HashSet<Protocol> = args
            .values_of("predefined-filter")
            .unwrap() // safe unwrap, because set by default by clap
            .map(Protocol::from_str)
            .flatten()
            .collect();
        let nameservers: Vec<_> = predefined::nameserver_configs()
            .into_iter()
            .filter(|x| filter.contains(&x.protocol()))
            .collect();
        let nameservers = NameServerConfigGroup::new(nameservers);
        debug!("Loaded {} nameservers.", nameservers.len());
        nameservers_group.merge(nameservers);
    }
    if let Some(path) = args.value_of("nameservers-from-file") {
        let nameservers = NameServerConfigGroup::from_file(&system_resolvers, path)
            .await
            .context("Failed to load nameservers from file")?;
        debug!("Loaded {} nameservers from file.", nameservers.len());
        nameservers_group.merge(nameservers);
    }

    Ok(nameservers_group)
}

fn load_resolver_group_opts(args: &ArgMatches) -> Result<ResolverGroupOpts> {
    let max_concurrent_servers = args
        .value_of("max-concurrent-servers")
        .map(|x| usize::from_str(x).unwrap())
        .unwrap(); // Safe unwrap, because clap's validation

    let resolver_group_opts = ResolverGroupOpts {
        max_concurrent: max_concurrent_servers,
    };
    debug!("Loaded resolver group opts.");

    Ok(resolver_group_opts)
}

fn load_resolver_opts(args: &ArgMatches) -> Result<ResolverOpts> {
    let ignore_system_resolv_opt = args.is_present("no-system-resolv-opt");
    let attempts = args.value_of("attempts").map(|x| usize::from_str(x).unwrap()).unwrap(); // Safe unwrap, because clap's validation
    let max_concurrent_requests = args
        .value_of("max-concurrent-requests")
        .map(|x| usize::from_str(x).unwrap())
        .unwrap(); // Safe unwrap, because clap's validation
    let timeout = args
        .value_of("timeout")
        .map(|x| u64::from_str(x).unwrap())
        .map(Duration::from_secs)
        .unwrap(); // Safe unwrap, because clap's validation
    let abort_on_error = !(args.is_present("no-abort-on-error") || args.is_present("no-aborts"));
    let abort_on_timeout = !(args.is_present("no-abort-on-timeout") || args.is_present("no-aborts"));

    let default_opts = if ignore_system_resolv_opt {
        Default::default()
    } else {
        ResolverOpts::from_system_config().context("Failed to load system resolver options")?
    };
    let resolver_opts = ResolverOpts {
        attempts,
        max_concurrent_requests,
        timeout,
        abort_on_error,
        abort_on_timeout,
        ..default_opts
    };
    debug!("Loaded resolver opts.");

    Ok(resolver_opts)
}

fn load_system_nameservers(args: &ArgMatches, ignore_system_nameservers: bool) -> Result<NameServerConfigGroup> {
    let mut system_nameserver_group = NameServerConfigGroup::new(Vec::new());

    if !ignore_system_nameservers {
        let nameservers = NameServerConfigGroup::from_system_config().context("Failed to load system name servers")?;
        debug!("Loaded {} system nameservers.", nameservers.len());
        system_nameserver_group.merge(nameservers);
    };

    if let Some(configs) = args.values_of("system nameservers") {
        let configs: Vec<_> = configs.map(NameServerConfig::from_str).collect();
        let configs: std::result::Result<Vec<_>, _> = configs.into_iter().collect();
        let nameservers: Vec<_> = configs.context("Failed to parse IP address for system nameserver")?;
        let nameservers = NameServerConfigGroup::new(nameservers);
        debug!("Loaded {} additional system nameservers.", nameservers.len());
        system_nameserver_group.merge(nameservers);
    };

    Ok(system_nameserver_group)
}

fn print_opts(group_opts: &ResolverGroupOpts, opts: &ResolverOpts) {
    println!(
        "Nameservers options: concurrent nameservers={}, attempts={}, concurrent requests={}, timeout={} s{}{}",
        group_opts.max_concurrent,
        opts.attempts,
        opts.max_concurrent_requests,
        opts.timeout.as_secs(),
        if opts.abort_on_error { ", abort on error" } else { "" },
        if opts.abort_on_timeout {
            ", abort on timeout"
        } else {
            ""
        },
    )
}

fn print_estimates(resolvers: &ResolverGroup, query: &MultiQuery) {
    let num_servers = resolvers.len();
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

async fn lookup(args: &ArgMatches<'_>, query: MultiQuery, resolvers: ResolverGroup) -> Lookups {
    if args.is_present("randomized-lookup") {
        resolvers.rnd_lookup(query).await
    } else {
        resolvers.lookup(query).await
    }
}

fn print_statistics(lookups: &Lookups, total_run_time: Duration) {
    let statistics = lookups.statistics();
    println!(
        "Received {} within {} ms of total run time.",
        statistics,
        total_run_time.as_millis()
    );
}

fn output(lookups: &Lookups) -> Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    let opts = SummaryOptions::default();
    let config = OutputConfig::summary(opts);
    let output = Output::new(config);
    output
        .output(&mut handle, &lookups)
        .context("Failed to print summary to stdout.")
}
