use std::convert::TryFrom;

use anyhow::Context;
use clap::{App, Arg, ArgMatches, SubCommand};
use crate::services::server_lists::ServerListSpec;
use std::str::FromStr;

pub fn subcommand() -> App<'static, 'static> {
    SubCommand::with_name("download-server-lists")
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
"#),
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

pub struct DownloadServerListConfig {
    pub server_list_specs: Vec<ServerListSpec>,
    pub output_file_path: String,
}

impl TryFrom<&ArgMatches<'_>> for DownloadServerListConfig {
    type Error = anyhow::Error;

    fn try_from(args: &ArgMatches) -> std::result::Result<Self, Self::Error> {
        let server_list_specs: Vec<_> = args
                .values_of("server_list_spec")
                .context("No server list specification")?
                .into_iter()
                .map(ServerListSpec::from_str)
                .collect();
        let server_list_specs: std::result::Result<Vec<_>, _> = server_list_specs.into_iter().collect();
        let server_list_specs = server_list_specs?;
        let config = DownloadServerListConfig {
            server_list_specs,
            output_file_path: args.value_of("output-file").context("No output file name specified")?.to_string(),
        };

        Ok(config)
    }
}
