use futures::future::join_all;
use std::io;
use std::io::Write;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::{App, Arg, ArgMatches};
use log::debug;

use mhost::{IntoName, Name, RecordType};
use mhost::nameserver::{NameServerConfig, NameServerConfigGroup};
use mhost::output::{Output, OutputConfig, OutputFormat};
use mhost::output::summary::SummaryOptions;
use mhost::resolver::{predefined, MultiQuery, ResolverConfigGroup, ResolverGroup, ResolverOpts};
use mhost::statistics::Statistics;

#[tokio::main]
async fn main() -> Result<()> {
    setup_logging();
    debug!("Set up logging.");
    let app = setup_clap();
    let args = app.get_matches();
    debug!("Parsed args.");

    run(args).await
}

fn setup_logging() {
    let start = std::time::Instant::now();
    env_logger::Builder::from_default_env()
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
        .arg(Arg::with_name("domain name")
            .required(true)
            .index(1)
            .help("domain name or IP address to lookup")
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
        )}

async fn run<'a>(args: ArgMatches<'a>) -> Result<()> {
    let ignore_system_resolv_opt = args.is_present("no-system-resolv-opt");
    let ignore_system_nameservers = args.is_present("no-system-nameservers");

    let domain_name = args.value_of("domain name")
        .context("No domain name to lookup specified")?;

    let is_ptr_lookup;
    let name: Name = if let Ok(ip_address) = IpAddr::from_str(domain_name) {
        is_ptr_lookup = true;
        debug!("Going to reverse lookup IP address.");
        ip_address.into()
    } else {
        is_ptr_lookup = false;
        debug!("Going to lookup name.");
        domain_name.into_name()
            .context("Failed to parse domain name")?
    };

    let system_resolver_ops = if ignore_system_resolv_opt {
        Default::default()
    } else {
        ResolverOpts::from_system_config()
            .context("Failed to load system resolver options")?
    };
    debug!("Set system resolver opts.");

    let additional_system_nameservers: NameServerConfigGroup = if let Some(configs) = args.values_of("system nameservers") {
        let configs: Vec<_> = configs
            .into_iter()
            .map(NameServerConfig::from_str)
            .collect();
        let configs: std::result::Result<Vec<_>, _> = configs.into_iter().collect();
        let nameservers: Vec<_> = configs
            .context("Failed to parse IP address for system nameserver")?;
        NameServerConfigGroup::new(nameservers)
    } else {
        NameServerConfigGroup::new(Vec::new())
    };
    debug!("Prepared {} additional system nameservers.", additional_system_nameservers.len());

    let system_nameservers: ResolverConfigGroup = if ignore_system_nameservers {
        additional_system_nameservers.into()
    } else {
        let mut system_nameservers = NameServerConfigGroup::from_system_config()
            .context("Failed to load system name servers")?;
        system_nameservers.merge(additional_system_nameservers);
        debug!("Loaded {} system nameservers.", system_nameservers.len());
        system_nameservers.into()
    };

    let mut system_resolvers = ResolverGroup::from_configs(system_nameservers, system_resolver_ops, Default::default()).await
        .context("Failed to create system resolvers")?;
    debug!("Created {} system resolvers.", system_resolvers.len());

    let nameservers: ResolverConfigGroup = if let Some(configs) = args.values_of("nameservers") {
        let configs: Vec<_> = configs
            .into_iter()
            .map(|str| NameServerConfig::from_str_with_resolution(&system_resolvers, str))
            .collect();
        let configs: mhost::Result<Vec<_>> = join_all(configs).await.into_iter().collect();
        let nameservers: Vec<_> = configs
            .context("Failed to parse IP address for system nameserver")?;
        NameServerConfigGroup::new(nameservers).into()
    } else {
        NameServerConfigGroup::new(Vec::new()).into()
    };
    let resolvers = ResolverGroup::from_configs(nameservers, Default::default(), Default::default()).await
        .context("Failed to load resolvers")?;
    debug!("Created {} resolvers.", resolvers.len());

    system_resolvers.merge(resolvers);

    if args.is_present("predefined") {
        let configs = predefined::resolver_configs();
        let predefined = ResolverGroup::from_configs(configs, Default::default(), Default::default()).await
            .context("Failed to load predefined resolvers")?;
        debug!("Created {} predefined resolvers.", predefined.len());
        system_resolvers.merge(predefined);
    }


    let record_types = if is_ptr_lookup {
        vec![RecordType::PTR]
    } else {
        let record_types: Vec<_> = args.values_of("record types")
            .context("No record types to look up specified")?
            .into_iter()
            .map(str::to_uppercase)
            .map(|x| RecordType::from_str(&x))
            .collect();
        let record_types: std::result::Result<Vec<_>, _> = record_types.into_iter().collect();
        record_types
            .context("Failed to parse record type")?
    };
    debug!("Prepared {} records for lookup.", record_types.len());

    let mq = MultiQuery::multi_record(name, record_types)
        .context("Failed to build query")?;
    debug!("Prepared query for lookup.");

    let start_time = Instant::now();
    let lookups = system_resolvers.lookup(mq).await;
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
        .context("Failed to print summary to stdout")
}