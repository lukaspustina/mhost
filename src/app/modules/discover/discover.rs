use std::io::Write;
use std::iter;
use std::str::FromStr;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use log::{debug, info};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::Serialize;
use trust_dns_resolver::IntoName;

use crate::app::cli::{print_estimates_lookups, print_opts, print_statistics, ExitStatus};
use crate::app::modules::discover::config::DiscoverConfig;
use crate::app::modules::discover::wordlist::Wordlist;
use crate::app::resolver::AppResolver;
use crate::app::{output, GlobalConfig, Partial};
use crate::output::styles::{self, ATTENTION_PREFIX, CAPTION_PREFIX, FINISHED_PREFIX, INFO_PREFIX, ITEMAZATION_PREFIX};
use crate::output::summary::{SummaryFormat, SummaryFormatter, SummaryOptions};
use crate::output::{OutputConfig, OutputType};
use crate::resolver::lookup::Uniquify;
use crate::resolver::{Lookups, MultiQuery};
use crate::{Name, RecordType};

pub struct Discover {}

impl Discover {
    pub async fn init<'a>(global_config: &'a GlobalConfig, config: &'a DiscoverConfig) -> Result<RequestAll<'a>> {
        if global_config.output == OutputType::Json && config.partial_results {
            return Err(anyhow!("JSON output is incompatible with partial result output"));
        }

        let domain_name: Name = config
            .domain_name
            .as_str()
            .into_name()
            .context("failed to parse domain name")?;
        let app_resolver = AppResolver::create_resolvers(global_config)
            .await?
            .with_single_server_lookup(config.single_server_lookup);

        // Showing partial results only makes sense, if the queried domain name is shown for every response,
        // because this modules generates domain names, e.g., wildcard resolution, wordlists
        let partial_output_config = Discover::create_partial_output_config(&global_config);

        if !global_config.quiet {
            print_opts(app_resolver.resolver_group_opts(), &app_resolver.resolver_opts());
        }

        Ok(RequestAll {
            global_config,
            config,
            partial_output_config,
            domain_name,
            app_resolver,
        })
    }

    fn create_partial_output_config(global_config: &&GlobalConfig) -> OutputConfig {
        let partial_output_config = OutputConfig::Summary {
            format: match &global_config.output_config {
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
    global_config: &'a GlobalConfig,
    config: &'a DiscoverConfig,
    partial_output_config: OutputConfig,
    domain_name: Name,
    app_resolver: AppResolver,
}

impl<'a> RequestAll<'a> {
    pub async fn request_all_records(self) -> Result<Partial<WildcardCheck<'a>>> {
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
            output::output(&self.partial_output_config, &lookups)?;
        }

        Ok(Partial::Next(WildcardCheck {
            global_config: self.global_config,
            config: self.config,
            partial_output_config: self.partial_output_config,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            total_run_time,
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
    partial_output_config: OutputConfig,
    domain_name: Name,
    app_resolver: AppResolver,
    total_run_time: Duration,
    lookups: Lookups,
}

impl<'a> WildcardCheck<'a> {
    async fn check_wildcard_resolution(self) -> Result<Partial<WordlistLookups<'a>>> {
        let rnd_names = WildcardCheck::rnd_names(self.config.rnd_names_number, self.config.rnd_names_len)
            .into_iter()
            .map(|x| Name::from_str(&x).unwrap().append_domain(&self.domain_name)); // Safe unwrap, we constructed the names
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
            output::output(&self.partial_output_config, &lookups)?;
        }

        Ok(Partial::Next(WordlistLookups {
            global_config: self.global_config,
            config: self.config,
            partial_output_config: self.partial_output_config,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            total_run_time: self.total_run_time + total_run_time,
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
            .map(|_| iter::repeat(()).map(|()| rng.sample(Alphanumeric)).take(len).collect())
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
    partial_output_config: OutputConfig,
    domain_name: Name,
    app_resolver: AppResolver,
    total_run_time: Duration,
    wildcard_resolutions: Option<Lookups>,
    lookups: Lookups,
}

impl<'a> WordlistLookups<'a> {
    async fn wordlist_lookups(self) -> Result<Partial<DiscoverResult<'a>>> {
        let wordlist = self.load_wordlist(&self.domain_name).await?;

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
        let lookups = self.filter_wildcard_responses(lookups);

        if !self.global_config.quiet && self.config.partial_results {
            print_statistics(&lookups, total_run_time);
        }
        if self.config.partial_results {
            output::output(&self.partial_output_config, &lookups)?;
        }

        // Merge lookups from this step with previous step
        let lookups = lookups.merge(self.lookups);

        Ok(Partial::Next(DiscoverResult {
            global_config: self.global_config,
            config: self.config,
            domain_name: self.domain_name,
            total_run_time: self.total_run_time + total_run_time,
            wildcard_resolutions: self.wildcard_resolutions,
            lookups,
        }))
    }

    fn filter_wildcard_responses(&self, lookups: Lookups) -> Lookups {
        if let Some(ref wildcards) = self.wildcard_resolutions {
            let wildcard_ips = wildcards.ips().unique().to_owned();
            let lookups = lookups
                .into_iter()
                .filter(|lookup| lookup.ips().unique().to_owned().is_disjoint(&wildcard_ips))
                .collect();
            Lookups::new(lookups)
        } else {
            lookups
        }
    }

    async fn load_wordlist(&self, append_domain_name: &Name) -> Result<Vec<Name>> {
        let wordlist: Vec<_> = if let Some(ref path) = self.config.wordlist_file_path {
            Wordlist::from_file(path).await?
        } else {
            Wordlist::default()?
        }
        .into_iter()
        .map(|x| x.clone().append_domain(&append_domain_name))
        .collect();
        debug!("Loaded wordlist with {} words", wordlist.len());

        Ok(wordlist)
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
    domain_name: Name,
    total_run_time: Duration,
    wildcard_resolutions: Option<Lookups>,
    lookups: Lookups,
}

impl<'a> DiscoverResult<'a> {
    fn output(self) -> Result<ExitStatus> {
        match self.global_config.output {
            OutputType::Json => self.json_output(),
            OutputType::Summary => self.summary_output(),
        }
    }

    fn json_output(self) -> Result<ExitStatus> {
        #[derive(Debug, Serialize)]
        struct Json {
            wildcard_resolutions: Option<Lookups>,
            lookups: Lookups,
        }
        impl SummaryFormatter for Json {
            fn output<W: Write>(&self, _: &mut W, _: &SummaryOptions) -> crate::Result<()> {
                unimplemented!()
            }
        }
        let data = Json {
            wildcard_resolutions: self.wildcard_resolutions,
            lookups: self.lookups,
        };

        output::output(&self.global_config.output_config, &data)?;
        Ok(ExitStatus::Ok)
    }

    fn summary_output(self) -> Result<ExitStatus> {
        let empty = Lookups::empty();
        let all_lookups = self
            .lookups
            .combine(self.wildcard_resolutions.as_ref().unwrap_or(&empty));

        if !self.global_config.quiet {
            println!("{}", styles::EMPH.paint(format!("{} Finished.", &*FINISHED_PREFIX)));
            print_statistics(&all_lookups, self.total_run_time);
            self.print_wildcard();
        }

        let mut names = self.unique_names();
        names.sort();

        for name in names {
            print_fancy_name_by_domain(&name, &self.domain_name);
        }

        Ok(ExitStatus::Ok)
    }

    fn print_wildcard(&self) {
        if let Some(ref wildcard) = self.wildcard_resolutions {
            let uniq_responses = wildcard.ips().unique().len();
            println!(
                "{} Wildcard resolution discovered: {} unique {} for {} random sub {}",
                styles::ATTENTION.paint(&*ATTENTION_PREFIX),
                uniq_responses,
                if uniq_responses > 1 { "answers" } else { "answer" },
                self.config.rnd_names_number,
                if self.config.rnd_names_number > 1 {
                    "domains"
                } else {
                    "domains"
                },
            );
        } else {
            println!(
                "{} No wildcard resolution discovered",
                styles::EMPH.paint(&*INFO_PREFIX)
            );
        }
    }

    fn unique_names(&self) -> Vec<Name> {
        self.lookups
            .records()
            .iter()
            .map(|x| x.name_labels())
            .unique()
            .to_owned()
            .into_iter()
            .collect()
    }
}

fn print_fancy_name_by_domain(name: &Name, domain_name: &Name) {
    if domain_name.zone_of(&name) {
        let domain_len = domain_name.num_labels();
        let sub_domain = Name::from_labels(name.iter().take((&name.num_labels() - domain_len) as usize)).unwrap();
        println!(
            " {} {}{}{}",
            &*ITEMAZATION_PREFIX,
            styles::EMPH.paint(&sub_domain),
            domain_name,
            if name.is_fqdn() { "." } else { "" }
        );
    } else {
        println!(" {} {}", &*ITEMAZATION_PREFIX, &name);
    }
}
