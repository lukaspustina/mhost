use std::convert::TryFrom;

use anyhow::Context;
use clap::ArgMatches;
use std::str::FromStr;

pub struct DiscoverConfig {
    pub domain_name: String,
    pub partial_results: bool,
    pub single_server_lookup: bool,
    pub wordlist_file_path: Option<String>,
    pub rnd_names_number: usize,
    pub rnd_names_len: usize,
    pub subdomains_only: bool,
}

impl TryFrom<&ArgMatches<'_>> for DiscoverConfig {
    type Error = anyhow::Error;

    fn try_from(args: &ArgMatches) -> std::result::Result<Self, Self::Error> {
        let config = DiscoverConfig {
            domain_name: args
                .value_of("domain name")
                .context("No domain name to lookup specified")?
                .to_string(),
            partial_results: args.is_present("partial-results"),
            single_server_lookup: args.is_present("single-server-lookup"),
            wordlist_file_path: args.value_of("wordlist-from-file").map(ToString::to_string),
            rnd_names_number: args
                .value_of("rnd-names-number")
                .map(|x| usize::from_str(x).context("failed to parse rnd-names-number"))
                .unwrap()?, // Safe unwrap, because of clap's validation
            rnd_names_len: args
                .value_of("rnd-names-len")
                .map(|x| usize::from_str(x).context("failed to parse rnd-names-len"))
                .unwrap()?, // Safe unwrap, because of clap's validation
            subdomains_only: args.is_present("subdomains-only"),
        };

        Ok(config)
    }
}
