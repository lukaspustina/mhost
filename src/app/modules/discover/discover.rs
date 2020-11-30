use std::collections::HashSet;
use std::iter;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Instant;

use anyhow::{Context, Result};
use indexmap::set::IndexSet;
use log::{debug, info};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use trust_dns_resolver::IntoName;

use crate::app::cli::{print_estimates_lookups, print_opts, print_statistics, ExitStatus};
use crate::app::modules::discover::config::DiscoverConfig;
use crate::app::modules::discover::wordlist::Wordlist;
use crate::app::resolver::AppResolver;
use crate::app::{output, GlobalConfig, Partial};
use crate::diff::SetDiffer;
use crate::nameserver::NameServerConfig;
use crate::output::styles::{self, ATTENTION_PREFIX, CAPTION_PREFIX, ERROR_PREFIX, OK_PREFIX};
use crate::resolver::lookup::Uniquify;
use crate::resolver::{Lookup, Lookups, MultiQuery, ResolverConfig};
use crate::resources::rdata::SOA;
use crate::{Name, RecordType};

pub struct Discover {}

impl Discover {
    pub async fn init<'a>(global_config: &'a GlobalConfig, config: &'a DiscoverConfig) -> Result<RequestAll<'a>> {
        let app_resolver = AppResolver::create_resolvers(global_config)
            .await?
            .with_single_server_lookup(config.single_server_lookup);

        // TODO: Set show-domain-names
        // Showing partial results only makes sense, if the queried domain name is shown for every response,
        // because this modules generates domain names, e.g., wildcard resolution, wordlists

        if !global_config.quiet {
            print_opts(app_resolver.resolver_group_opts(), &app_resolver.resolver_opts());
        }

        Ok(RequestAll {
            global_config,
            config,
            app_resolver,
        })
    }
}

pub struct RequestAll<'a> {
    global_config: &'a GlobalConfig,
    config: &'a DiscoverConfig,
    app_resolver: AppResolver,
}

impl<'a> RequestAll<'a> {
    pub async fn request_all_records(self) -> Result<Partial<WildcardCheck<'a>>> {
        let query = MultiQuery::multi_record(
            self.config.domain_name.as_str(),
            vec![
                RecordType::A,
                RecordType::AAAA,
                RecordType::ANY,
                RecordType::ANAME,
                RecordType::CNAME,
                RecordType::MX,
                RecordType::NS,
                RecordType::SRV,
                RecordType::SOA,
                RecordType::TXT,
            ],
        )?;

        if !self.global_config.quiet && self.config.partial_results {
            println!(
                "{}",
                styles::EMPH.paint(format!("{} Requesting all record types.", &*CAPTION_PREFIX))
            );
            print_estimates_lookups(&self.app_resolver.resolvers(), &query);
        }

        info!("Requesting all record types.");
        let start_time = Instant::now();
        let lookups: Lookups = self.app_resolver.lookup(query).await?;
        let total_run_time = Instant::now() - start_time;
        info!("Finished Lookups.");

        if !self.global_config.quiet && self.config.partial_results {
            print_statistics(&lookups, total_run_time);
        }
        if self.config.partial_results {
            output::output(&self.global_config.output_config, &lookups)?;
        }

        Ok(Partial::Next(WildcardCheck {
            global_config: self.global_config,
            config: self.config,
            app_resolver: self.app_resolver,
            lookups,
        }))
    }
}

impl<'a> Partial<WildcardCheck<'a>> {
    pub async fn check_wildcard_resolution(self) -> Result<Partial<WordlistLookups<'a>>> {
        match self {
            Partial::Next(next) => next.check_wildcard_resolution().await,
            Partial::ExitStatus(e) => Ok(Partial::ExitStatus(e)),
        }
    }
}

pub struct WildcardCheck<'a> {
    global_config: &'a GlobalConfig,
    config: &'a DiscoverConfig,
    app_resolver: AppResolver,
    lookups: Lookups,
}

impl<'a> WildcardCheck<'a> {
    async fn check_wildcard_resolution(self) -> Result<Partial<WordlistLookups<'a>>> {
        let domain_name: Name = self
            .config
            .domain_name
            .as_str()
            .into_name()
            .context("failed to parse domain name")?;

        let rnd_names = WildcardCheck::rnd_names(self.config.rnd_names_number, self.config.rnd_names_len)
            .into_iter()
            .map(|x| Name::from_str(&x).unwrap().append_domain(&domain_name)); // Safe unwrap, we constructed the names
        let query = MultiQuery::new(rnd_names, vec![RecordType::A, RecordType::AAAA])?;

        if !self.global_config.quiet && self.config.partial_results {
            println!(
                "{}",
                styles::EMPH.paint(format!("{} Checking wildcard resolution.", &*CAPTION_PREFIX))
            );
            print_estimates_lookups(&self.app_resolver.resolvers(), &query);
        }

        info!("Checking wildcard resolution.");
        let start_time = Instant::now();
        let lookups: Lookups = self.app_resolver.lookup(query).await?;
        let total_run_time = Instant::now() - start_time;
        info!("Finished Lookups.");

        if !self.global_config.quiet && self.config.partial_results {
            print_statistics(&lookups, total_run_time);
        }
        if self.config.partial_results {
            output::output(&self.global_config.output_config, &lookups)?;
        }

        Ok(Partial::Next(WordlistLookups {
            global_config: self.global_config,
            config: self.config,
            app_resolver: self.app_resolver,
            wildcard_resolutions: if lookups.has_records() { Some(lookups) } else { None },
            lookups: self.lookups,
        }))
    }

    fn rnd_names(number: usize, len: usize) -> Vec<String> {
        info!(
            "Generating {} number of random domain names with length {}",
            number, len
        );
        let mut rng = thread_rng();
        (0..number)
            .map(|i| iter::repeat(()).map(|()| rng.sample(Alphanumeric)).take(len).collect())
            .inspect(|x| debug!("Generated random domain name: '{}'", x))
            .collect()
    }
}

impl<'a> Partial<WordlistLookups<'a>> {
    pub async fn wordlist_lookups(self) -> Result<Partial<DiscoverResult<'a>>> {
        match self {
            Partial::Next(next) => next.wordlist_lookups().await,
            Partial::ExitStatus(e) => Ok(Partial::ExitStatus(e)),
        }
    }
}

pub struct WordlistLookups<'a> {
    global_config: &'a GlobalConfig,
    config: &'a DiscoverConfig,
    app_resolver: AppResolver,
    wildcard_resolutions: Option<Lookups>,
    lookups: Lookups,
}

impl<'a> WordlistLookups<'a> {
    async fn wordlist_lookups(self) -> Result<Partial<DiscoverResult<'a>>> {
        let domain_name: Name = self
            .config
            .domain_name
            .as_str()
            .into_name()
            .context("failed to parse domain name")?;
        let wordlist = Wordlist::default()?
            .into_iter()
            .map(|x| x.clone().append_domain(&domain_name));
        let query = MultiQuery::new(
            wordlist,
            vec![
                RecordType::A,
                RecordType::AAAA,
                RecordType::MX,
                RecordType::NS,
                RecordType::SRV,
                RecordType::SOA,
            ],
        )?;

        if !self.global_config.quiet && self.config.partial_results {
            println!(
                "{}",
                styles::EMPH.paint(format!("{} Wordlist lookups.", &*CAPTION_PREFIX))
            );
            print_estimates_lookups(&self.app_resolver.resolvers(), &query);
        }

        info!("Wordlist lookups.");
        let start_time = Instant::now();
        let lookups: Lookups = self.app_resolver.lookup(query).await?;
        let total_run_time = Instant::now() - start_time;
        info!("Finished Lookups.");

        // Filter wildcard responses
        // TODO: Currently only for A records
        let lookups = if let Some(ref wildcards) = self.wildcard_resolutions {
            let wildcards = wildcards.a().unique().to_owned();
            let lookups = lookups
                .into_iter()
                .filter(|x| {
                    let ips = x.a();
                    if ips.is_empty() {
                        true
                    } else {
                        let ips = ips.unique().to_owned();
                        ips.intersection(&wildcards).into_iter().next().is_none()
                    }
                })
                .collect();
            Lookups::new(lookups)
        } else {
            lookups
        };

        if !self.global_config.quiet && self.config.partial_results {
            print_statistics(&lookups, total_run_time);
        }
        if self.config.partial_results {
            output::output(&self.global_config.output_config, &lookups)?;
        }

        // TODO: Merge Lookups

        Ok(Partial::Next(DiscoverResult {
            global_config: self.global_config,
            config: self.config,
            wildcard_resolutions: self.wildcard_resolutions,
            lookups: self.lookups,
        }))
    }
}

impl<'a> Partial<DiscoverResult<'a>> {
    pub fn output(self) -> Result<ExitStatus> {
        match self {
            Partial::Next(next) => next.output(),
            Partial::ExitStatus(e) => Ok(e),
        }
    }
}

pub struct DiscoverResult<'a> {
    global_config: &'a GlobalConfig,
    config: &'a DiscoverConfig,
    wildcard_resolutions: Option<Lookups>,
    lookups: Lookups,
}

impl<'a> DiscoverResult<'a> {
    fn output(self) -> Result<ExitStatus> {
        Ok(ExitStatus::Ok)
    }
}
