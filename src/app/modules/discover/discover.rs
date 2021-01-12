// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::io::Write;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::Serialize;
use tracing::{debug, info};

use crate::app::console::Fmt;
use crate::app::modules::discover::config::DiscoverConfig;
use crate::app::modules::discover::wordlist::Wordlist;
use crate::app::modules::{AppModule, Environment, PartialResult, RunInfo};
use crate::app::output::summary::{SummaryFormat, SummaryFormatter, SummaryOptions};
use crate::app::output::{OutputConfig, OutputType};
use crate::app::resolver::AppResolver;
use crate::app::utils::time;
use crate::app::{output, AppConfig, ExitStatus};
use crate::resolver::lookup::Uniquify;
use crate::resolver::{Lookup, Lookups, MultiQuery};
use crate::{Name, RecordType};
use nom::lib::std::collections::HashSet;

pub struct Discover {}

impl AppModule<DiscoverConfig> for Discover {}

impl Discover {
    pub async fn init<'a>(app_config: &'a AppConfig, config: &'a DiscoverConfig) -> PartialResult<RequestAll<'a>> {
        if app_config.output == OutputType::Json && config.partial_results {
            return Err(anyhow!("JSON output is incompatible with partial result output").into());
        }

        let env = Self::init_env(app_config, config)?;
        let domain_name = env.name_builder.from_str(&config.domain_name)?;
        let app_resolver = AppResolver::create_resolvers(app_config).await?;

        // Showing partial results only makes sense, if the queried domain name is shown for every response,
        // because this modules generates domain names, e.g., wildcard resolution, word lists
        let partial_output_config = Discover::create_partial_output_config(&env.app_config);

        env.console
            .print_resolver_opts(app_resolver.resolver_group_opts(), &app_resolver.resolver_opts());

        Ok(RequestAll {
            env,
            partial_output_config,
            domain_name,
            app_resolver,
        })
    }

    fn create_partial_output_config(app_config: &AppConfig) -> OutputConfig {
        let partial_output_config = OutputConfig::Summary {
            format: match &app_config.output_config {
                OutputConfig::Json { .. } => SummaryFormat::new(SummaryOptions::new(
                    SummaryOptions::default().human(),
                    SummaryOptions::default().condensed(),
                    true,
                )),
                OutputConfig::Summary { format } => SummaryFormat::new(SummaryOptions::new(
                    format.opts().human(),
                    format.opts().condensed(),
                    true,
                )),
            },
        };
        partial_output_config
    }
}

pub struct RequestAll<'a> {
    env: Environment<'a, DiscoverConfig>,
    partial_output_config: OutputConfig,
    domain_name: Name,
    app_resolver: AppResolver,
}

impl<'a> RequestAll<'a> {
    pub async fn request_all_records(self) -> PartialResult<WildcardCheck<'a>> {
        let query = MultiQuery::multi_record(
            self.domain_name.clone(),
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

        self.env
            .console
            .print_partial_headers("Requesting all record types.", &self.app_resolver.resolvers(), &query);

        info!("Requesting all record types.");
        let (lookups, run_time) = time(self.app_resolver.lookup(query)).await?;
        info!("Finished Lookups.");

        self.env
            .console
            .print_partial_results(&self.partial_output_config, &lookups, run_time)?;

        Ok(WildcardCheck {
            env: self.env,
            partial_output_config: self.partial_output_config,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            run_time,
            lookups,
        })
    }
}

pub struct WildcardCheck<'a> {
    env: Environment<'a, DiscoverConfig>,
    partial_output_config: OutputConfig,
    domain_name: Name,
    app_resolver: AppResolver,
    run_time: Duration,
    lookups: Lookups,
}

impl<'a> WildcardCheck<'a> {
    pub async fn check_wildcard_resolution(self) -> PartialResult<WordlistLookups<'a>> {
        let rnd_names =
            WildcardCheck::rnd_names(self.env.mod_config.rnd_names_number, self.env.mod_config.rnd_names_len)
                .into_iter()
                .map(|x| Name::from_str(&x).unwrap().append_domain(&self.domain_name)); // Safe unwrap, we constructed the names
        let query = MultiQuery::new(rnd_names, vec![RecordType::A, RecordType::AAAA])?;

        self.env
            .console
            .print_partial_headers("Checking wildcard resolution.", &self.app_resolver.resolvers(), &query);

        info!("Checking wildcard resolution.");
        let (lookups, run_time) = time(self.app_resolver.lookup(query)).await?;
        info!("Finished Lookups.");

        self.env
            .console
            .print_partial_results(&self.partial_output_config, &lookups, run_time)?;

        Ok(WordlistLookups {
            env: self.env,
            partial_output_config: self.partial_output_config,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            run_time: self.run_time + run_time,
            wildcard_lookups: if lookups.has_records() { Some(lookups) } else { None },
            lookups: self.lookups,
        })
    }

    fn rnd_names(number: usize, len: usize) -> Vec<String> {
        info!(
            "Generating {} number of random domain names with length {}",
            number, len
        );
        let mut rng = thread_rng();
        (0..number)
            .map(|_| (&mut rng).sample_iter(Alphanumeric).take(len).map(char::from).collect())
            .inspect(|x| debug!("Generated random domain name: '{}'", x))
            .collect()
    }
}

pub struct WordlistLookups<'a> {
    env: Environment<'a, DiscoverConfig>,
    partial_output_config: OutputConfig,
    domain_name: Name,
    app_resolver: AppResolver,
    run_time: Duration,
    wildcard_lookups: Option<Lookups>,
    lookups: Lookups,
}

impl<'a> WordlistLookups<'a> {
    pub async fn wordlist_lookups(self) -> PartialResult<OutputDiscoverResult<'a>> {
        let wordlist = self.load_wordlist(&self.domain_name).await?;

        let query = MultiQuery::new(
            wordlist,
            vec![
                RecordType::A,
                RecordType::AAAA,
                RecordType::ANAME,
                RecordType::CNAME,
                RecordType::MX,
                RecordType::NS,
                RecordType::SRV,
                RecordType::SOA,
            ],
        )?;

        self.env
            .console
            .print_partial_headers("Wordlist lookups.", &self.app_resolver.resolvers(), &query);

        info!("Wordlist lookups.");
        let (lookups, run_time) = time(self.app_resolver.lookup(query)).await?;
        info!("Finished Lookups.");

        // Filter wildcard responses
        let lookups = self.filter_wildcard_responses(lookups);

        self.env
            .console
            .print_partial_results(&self.partial_output_config, &lookups, run_time)?;

        // Merge lookups from this step with previous step
        let lookups = lookups.merge(self.lookups);

        Ok(OutputDiscoverResult {
            env: self.env,
            domain_name: self.domain_name,
            run_time: self.run_time + run_time,
            wildcard_lookups: self.wildcard_lookups,
            lookups,
        })
    }

    fn filter_wildcard_responses(&self, lookups: Lookups) -> Lookups {
        if let Some(ref wildcards) = self.wildcard_lookups {
            // These are the resolutions we've received during the wildcard check
            let wildcard_recods = wildcards.records();
            let wildcard_resolutions = wildcard_recods.iter().unique().iter().map(|x| x.rdata()).collect();

            // If a wordlist resolution points to a wildcard resolution, then it is a wildcard resolution by itself.
            let lookups = lookups
                .into_iter()
                .filter(|lookup: &Lookup| {
                    let records = lookup.records();
                    let set: HashSet<_> = records.iter().unique().iter().map(|x| x.rdata()).collect();
                    set.is_disjoint(&wildcard_resolutions)
                })
                .collect();
            Lookups::new(lookups)
        } else {
            lookups
        }
    }

    async fn load_wordlist(&self, append_domain_name: &Name) -> Result<Vec<Name>> {
        let wordlist: Vec<_> = if let Some(ref path) = self.env.mod_config.wordlist_file_path {
            Wordlist::from_file(path).await?
        } else {
            Wordlist::default()?
        }
        .into_iter()
        .map(|x| x.append_domain(&append_domain_name))
        .collect();
        debug!("Loaded wordlist with {} words", wordlist.len());

        Ok(wordlist)
    }
}

pub struct OutputDiscoverResult<'a> {
    env: Environment<'a, DiscoverConfig>,
    domain_name: Name,
    run_time: Duration,
    wildcard_lookups: Option<Lookups>,
    lookups: Lookups,
}

impl<'a> OutputDiscoverResult<'a> {
    pub fn output(self) -> PartialResult<ExitStatus> {
        match self.env.app_config.output {
            OutputType::Json => self.json_output(),
            OutputType::Summary => self.summary_output(),
        }
    }

    fn json_output(self) -> PartialResult<ExitStatus> {
        #[derive(Debug, Serialize)]
        struct Json {
            info: RunInfo,
            wildcard_resolutions: Option<Lookups>,
            lookups: Lookups,
        }
        impl SummaryFormatter for Json {
            fn output<W: Write>(&self, _: &mut W, _: &SummaryOptions) -> crate::Result<()> {
                unimplemented!()
            }
        }
        let data = Json {
            info: self.env.run_info,
            wildcard_resolutions: self.wildcard_lookups,
            lookups: self.lookups,
        };

        output::output(&self.env.app_config.output_config, &data)?;
        Ok(ExitStatus::Ok)
    }

    fn summary_output(self) -> PartialResult<ExitStatus> {
        let empty = Lookups::empty();
        let all_lookups = self.lookups.combine(self.wildcard_lookups.as_ref().unwrap_or(&empty));

        self.env.console.print_finished();
        if self.env.console.not_quiet() {
            self.env.console.print_statistics(&all_lookups, self.run_time);
            self.print_wildcard();
        }
        self.print_fancy_names(&all_lookups);

        Ok(ExitStatus::Ok)
    }

    fn print_wildcard(&self) {
        if let Some(ref wildcard) = self.wildcard_lookups {
            let uniq_responses = wildcard.ips().unique().len();
            self.env.console.attention(format!(
                "Wildcard resolution discovered: {} unique {} for {} random sub {}",
                uniq_responses,
                if uniq_responses > 1 { "answers" } else { "answer" },
                self.env.mod_config.rnd_names_number,
                if self.env.mod_config.rnd_names_number > 1 {
                    "domains"
                } else {
                    "domain"
                },
            ));
        } else {
            self.env.console.info("No wildcard resolution discovered");
        }
    }

    fn print_fancy_names(&self, lookups: &Lookups) {
        let mut names = if self.env.mod_config.subdomains_only {
            self.unique_names(lookups)
                .into_iter()
                .filter(|x| self.domain_name.zone_of(x))
                .collect()
        } else {
            self.unique_names(lookups)
        };
        names.sort();
        for name in names {
            self.print_fancy_name_by_domain(&name, &self.domain_name);
        }
    }

    fn unique_names(&self, lookups: &Lookups) -> Vec<Name> {
        let query_names = self
            .lookups
            .iter()
            .filter(|x| x.result().is_response())
            .map(|x| x.query().name());
        lookups
            .records()
            .iter()
            .map(|x| x.associated_name())
            .chain(query_names)
            .unique()
            .to_owned()
            .into_iter()
            .collect()
    }

    fn print_fancy_name_by_domain(&self, name: &Name, domain_name: &Name) {
        if domain_name.zone_of(&name) {
            let domain_len = domain_name.num_labels();
            let sub_domain = Name::from_labels(name.iter().take((name.num_labels() - domain_len) as usize)).unwrap();
            self.env
                .console
                .itemize(format!("{}{}", Fmt::emph(&sub_domain), domain_name,));
        } else {
            self.env.console.itemize(name.to_string());
        }
    }
}
