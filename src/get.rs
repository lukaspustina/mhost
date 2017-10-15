// Arbitrary list of public DNS servers
static DEFAULT_DNS_SERVERS: &'static [&str] = &[
    // "Level3",
    "209.244.0.3",
    "209.244.0.4",
    // "Verisign",
    "64.6.64.6",
    "64.6.65.6",
    // "Google",
    "8.8.8.8",
    "8.8.4.4",
    // "DNS.WATCH",
    "84.200.69.80",
    "84.200.70.40",
    // "OpenDNS Home",
    "208.67.222.222",
    "208.67.220.220",
    // "SafeDNS",
    "195.46.39.39",
    "195.46.39.40",
    // "Dyn",
    "216.146.35.35",
    "216.146.36.36",
    // "FreeDNS",
    "37.235.1.174",
    "37.235.1.177",
    // "Alternate DNS",
    "198.101.242.72",
    "23.253.163.53",
    // "Level3",
    "209.244.0.3",
    "209.244.0.4",
    // "Verisign",
    "64.6.64.6",
    "64.6.65.6",
    // "Google",
    "8.8.8.8",
    "8.8.4.4",
    // "DNS.WATCH",
    "84.200.69.80",
    "84.200.70.40",
    // "OpenDNS Home",
    "208.67.222.222",
    "208.67.220.220",
    // "SafeDNS",
    "195.46.39.39",
    "195.46.39.40",
    // "Dyn",
    "216.146.35.35",
    "216.146.36.36",
    // "FreeDNS",
    "37.235.1.174",
    "37.235.1.177",
    // "Alternate DNS",
    "198.101.242.72",
    "23.253.163.53",
    // "Level3",
    "209.244.0.3",
    "209.244.0.4",
    // "Verisign",
    "64.6.64.6",
    "64.6.65.6",
    // "Google",
    "8.8.8.8",
    "8.8.4.4",
    // "DNS.WATCH",
    "84.200.69.80",
    "84.200.70.40",
    // "OpenDNS Home",
    "208.67.222.222",
    "208.67.220.220",
    // "SafeDNS",
    "195.46.39.39",
    "195.46.39.40",
    // "Dyn",
    "216.146.35.35",
    "216.146.36.36",
    // "FreeDNS",
    "37.235.1.174",
    "37.235.1.177",
    // "Alternate DNS",
    "198.101.242.72",
    "23.253.163.53",
];

static DEFAULT_RECORD_TYPES: &'static [&str] = &["a", "aaaa", "mx"];

use ungefiltert_surfen::{self, Server as UngefiltertServer};

use futures::{Future, future};
use resolv_conf;
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::str::FromStr;
use tokio_core::reactor::Handle;
use trust_dns::rr::RecordType;

pub fn dns_servers(
    loop_handle: &Handle,
    servers: Option<Vec<String>>,
    use_predefined_server: bool,
    dont_use_local_servers: bool,
    ungefiltert_surfen_ids: Option<Vec<String>>
) -> Box<Future<Item=Vec<IpAddr>, Error=Error>> {
    let from_args = future::ok::<Vec<IpAddr>, Error>({
        let mut dns_servers: Vec<IpAddr> = Vec::new();
        if let Some(servers) = servers {
            dns_servers.extend(servers.into_iter().map(|server| {
                IpAddr::from_str(&server).unwrap()
            }));
        }
        if use_predefined_server {
            dns_servers.extend(DEFAULT_DNS_SERVERS.iter().map(|server| {
                IpAddr::from_str(server).unwrap()
            }));
        }
        if !dont_use_local_servers {
            dns_servers.extend(dns_servers_from_resolv_conf().unwrap());
        }

        dns_servers
    }).map_err(move |e| {
        Error::with_chain(e, ErrorKind::ServerIpAddrParsingError)
    });

    let us: Vec<_> = ungefiltert_surfen_ids.unwrap_or_else(|| vec![])
        .iter()
        .map(|id| ungefiltert_surfen::retrieve_servers(&loop_handle, id))
        .collect();
    let from_ungefiltert = future::join_all(us)
        .map(move |answers| {
            answers.into_iter().fold(Vec::new(), |mut acc, servers: Vec<UngefiltertServer>| {
                acc.extend(servers);
                acc
            })
                .iter()
                .map(|server| IpAddr::from_str(&server.ip).unwrap())
                .collect()
        })
        .map_err(move |e| {
            e.into()
        });

    Box::new(from_args.join(from_ungefiltert)
        .map(|(mut r1, r2): (Vec<_>, Vec<_>)| {
            r1.extend(r2);
            r1
        })
    )
}

fn dns_servers_from_resolv_conf() -> Result<Vec<IpAddr>> {
    let mut buf = Vec::with_capacity(4096);
    let mut f = File::open("/etc/resolv.conf").chain_err(
        || ErrorKind::ResolvConfError,
    )?;
    f.read_to_end(&mut buf).unwrap();
    let cfg = resolv_conf::Config::parse(&buf[..]).chain_err(|| {
        ErrorKind::ResolvConfError
    })?;
    Ok(cfg.nameservers)
}

pub fn record_types(record_types: Option<Vec<String>>) -> Result<Vec<RecordType>> {
    let record_types = if let Some(rt) = record_types {
        rt
            .iter()
            .map(|rt| RecordType::from_str(&rt.to_uppercase()).unwrap())
            .collect()
    } else {
        DEFAULT_RECORD_TYPES
            .iter()
            .map(|rt| RecordType::from_str(&rt.to_uppercase()).unwrap())
            .collect()
    };

    Ok(record_types)
}

error_chain! {
    errors {
        ResolvConfError {
            description("failed to parse /etc/resolv.conf")
            display("failed to parse /etc/resolv.cons")
        }

        ServerIpAddrParsingError {
            description("failed to parse server IP address")
            display("failed to parse server IP address")
        }

        ResoureRecordTypeParsingError {
            description("failed to parse resource record type")
            display("failed to parse resource record type")
        }
    }

    links {
        Ungefiltert(ungefiltert_surfen::Error, ungefiltert_surfen::ErrorKind);
    }
}
