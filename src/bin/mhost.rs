use std::io;
use std::io::Write;
use std::str::FromStr;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::{App, Arg, ArgMatches, Values};
use futures::future::join_all;
use log::{debug, LevelFilter};

use mhost::nameserver::{self, NameServerConfig, NameServerConfigGroup};
use mhost::output::summary::SummaryOptions;
use mhost::output::{Output, OutputConfig, OutputFormat};
use mhost::resolver::{predefined, MultiQuery, ResolverConfigGroup, ResolverGroup, ResolverOpts};
use mhost::statistics::Statistics;
use mhost::{IpNetwork, RecordType};

#[tokio::main]
async fn main() -> Result<()> {
    let app = setup_clap();
    let args = app.get_matches();

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
        .arg(Arg::with_name("v")
            .short("v")
            .multiple(true)
            .help("Sets the level of verbosity"))
        .arg(Arg::with_name("domain name")
            .required_unless("list-predefined")
            .index(1)
            .value_name("NAME | IP ADDR | CIDR block")
            .help("domain name, IP address, or CIDR block")
            .long_help(
                "* DOMAIN NAME may be any valid DNS name, e.g., lukas.pustina.de
* IP ADDR may be any valid IPv4 or IPv4 address, e.g., 192.168.0.1
* CIDR block may be any valid IPv4 or IPv6 subnet in CIDR notation, e.g., 192.168.0.1/24
  all valid IP addresses of a CIDR block will be queried for a reverse lookup"
            )
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
            .help("Sets record types to lookup, will be ignored in case of IP address lookup")
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
            .help("Adds system nameservers for system lookups; only IP addresses allowed")
        )
        .arg(Arg::with_name("nameservers")
            .short("s")
            .long("nameserver")
            .value_name("HOSTNAME | IP ADDR")
            .takes_value(true)
            .multiple(true)
            .help("Uses nameservers for lookups; if non given, only system nameservers will be used")
        )
        .arg(Arg::with_name("predefined")
            .short("p")
            .long("predefined")
            .help("Uses predefined nameservers")
        )
        .arg(Arg::with_name("list-predefined")
            .long("list-predefined")
            .conflicts_with("domain name")
            .help("Lists all predefined nameservers")
        )
        .arg(Arg::with_name("randomized-lookup")
            .short("R")
            .long("randomized-lookup")
            .help("Switches into randomize lookup mode: every query will be send just once to a one randomly chosen nameserver. This can be used to distribute queries among the available nameservers.")
        )
}

async fn run(args: ArgMatches<'_>) -> Result<()> {
    if args.is_present("list-predefined") {
        list_predefined_nameservers();
        return Ok(());
    }

    let ignore_system_resolv_opt = args.is_present("no-system-resolv-opt");
    let ignore_system_nameservers = args.is_present("no-system-nameservers");

    let domain_name = args
        .value_of("domain name")
        .context("No domain name to lookup specified")?;
    let query = if let Ok(ip_network) = IpNetwork::from_str(domain_name) {
        ptr_query(ip_network)?
    } else {
        let record_types_arg = args
            .values_of("record types")
            .context("No record types for name lookup specified")?;
        name_query(domain_name, record_types_arg)?
    };

    let system_resolver_ops = if ignore_system_resolv_opt {
        Default::default()
    } else {
        ResolverOpts::from_system_config().context("Failed to load system resolver options")?
    };
    debug!("Set system resolver opts.");

    let additional_system_nameservers: NameServerConfigGroup =
        if let Some(configs) = args.values_of("system nameservers") {
            let configs: Vec<_> = configs.map(NameServerConfig::from_str).collect();
            let configs: std::result::Result<Vec<_>, _> = configs.into_iter().collect();
            let nameservers: Vec<_> = configs.context("Failed to parse IP address for system nameserver")?;
            NameServerConfigGroup::new(nameservers)
        } else {
            NameServerConfigGroup::new(Vec::new())
        };
    debug!(
        "Prepared {} additional system nameservers.",
        additional_system_nameservers.len()
    );

    let system_nameservers: ResolverConfigGroup = if ignore_system_nameservers {
        additional_system_nameservers.into()
    } else {
        let mut system_nameservers =
            NameServerConfigGroup::from_system_config().context("Failed to load system name servers")?;
        system_nameservers.merge(additional_system_nameservers);
        debug!("Loaded {} system nameservers.", system_nameservers.len());
        system_nameservers.into()
    };

    let mut system_resolvers = ResolverGroup::from_configs(system_nameservers, system_resolver_ops, Default::default())
        .await
        .context("Failed to create system resolvers")?;
    debug!("Created {} system resolvers.", system_resolvers.len());

    let nameservers: ResolverConfigGroup = if let Some(configs) = args.values_of("nameservers") {
        let configs: Vec<_> = configs
            .map(|str| NameServerConfig::from_str_with_resolution(&system_resolvers, str))
            .collect();
        let configs: mhost::Result<Vec<_>> = join_all(configs).await.into_iter().collect();
        let nameservers: Vec<_> = configs.context("Failed to parse IP address for system nameserver")?;
        NameServerConfigGroup::new(nameservers).into()
    } else {
        NameServerConfigGroup::new(Vec::new()).into()
    };
    let resolvers = ResolverGroup::from_configs(nameservers, Default::default(), Default::default())
        .await
        .context("Failed to load resolvers")?;
    debug!("Created {} resolvers.", resolvers.len());

    system_resolvers.merge(resolvers);

    if args.is_present("predefined") {
        let configs = predefined::resolver_configs();
        let predefined = ResolverGroup::from_configs(configs, Default::default(), Default::default())
            .await
            .context("Failed to load predefined resolvers")?;
        debug!("Created {} predefined resolvers.", predefined.len());
        system_resolvers.merge(predefined);
    }

    let start_time = Instant::now();
    let lookups = if args.is_present("randomized-lookup") {
        system_resolvers.rnd_lookup(query).await
    } else {
        system_resolvers.lookup(query).await
    };
    let total_run_time = Instant::now() - start_time;

    let statistics = lookups.statistics();
    println!(
        "Received {} within {} ms of total run time.",
        statistics,
        total_run_time.as_millis()
    );

    let stdout = io::stdout();
    let mut handle = stdout.lock();

    let opts = SummaryOptions::default();
    let config = OutputConfig::summary(opts);
    let output = Output::new(config);
    output
        .output(&mut handle, &lookups)
        .context("Failed to print summary to stdout.")
}

fn list_predefined_nameservers() {
    println!("List of predefined servers:");
    for ns in nameserver::predefined::name_server_configs() {
        println!("* {}", ns);
    }
}

fn ptr_query(ip_network: IpNetwork) -> Result<MultiQuery> {
    let q = MultiQuery::multi_name(ip_network.iter(), RecordType::PTR).context("Failed to create query")?;
    debug!("Prepared query for reverse lookups.");
    Ok(q)
}

fn name_query(name: &str, record_types: Values) -> Result<MultiQuery> {
    let record_types: Vec<_> = record_types
        .map(str::to_uppercase)
        .map(|x| RecordType::from_str(&x))
        .collect();
    let record_types: std::result::Result<Vec<_>, _> = record_types.into_iter().collect();
    let record_types = record_types.context("Failed to parse record type")?;
    let record_types_len = record_types.len();

    let q = MultiQuery::multi_record(name, record_types).context("Failed to build query")?;
    debug!("Prepared query for name lookup for {} record types.", record_types_len);
    Ok(q)
}
