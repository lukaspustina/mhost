// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashMap;
use std::io::Write;
use std::str::FromStr;
use std::time::Duration;

use anyhow::anyhow;
use serde::Serialize;
use tracing::info;

use crate::app::console::Fmt;
use crate::app::modules::domain_lookup::config::DomainLookupConfig;
use crate::app::modules::domain_lookup::subdomain_spec::{self, Category, SubdomainEntry};
use crate::app::modules::{AppModule, Environment, PartialResult, RunInfo};
use crate::app::output::summary::{SummaryFormat, SummaryFormatter, SummaryOptions};
use crate::app::output::{OutputConfig, OutputType};
use crate::app::resolver::AppResolver;
use crate::app::utils::time;
use crate::app::{output, AppConfig, ExitStatus};
use crate::resolver::lookup::Lookup;
use crate::resolver::{Lookups, MultiQuery};
use crate::{Name, RecordType};

pub struct DomainLookup {}

impl AppModule<DomainLookupConfig> for DomainLookup {}

impl DomainLookup {
    pub async fn init<'a>(app_config: &'a AppConfig, config: &'a DomainLookupConfig) -> PartialResult<RunLookups<'a>> {
        if app_config.output == OutputType::Json && config.partial_results {
            return Err(anyhow!("JSON output is incompatible with partial result output").into());
        }

        let env = Self::init_env(app_config, config)?;
        let domain_name = env.name_builder.from_str(&config.domain_name)?;
        let app_resolver = AppResolver::create_resolvers(app_config).await?;

        let partial_output_config = DomainLookup::create_partial_output_config(env.app_config);

        env.console
            .print_resolver_opts(app_resolver.resolver_group_opts(), app_resolver.resolver_opts());

        Ok(RunLookups {
            env,
            partial_output_config,
            domain_name,
            app_resolver,
        })
    }

    fn create_partial_output_config(app_config: &AppConfig) -> OutputConfig {
        OutputConfig::Summary {
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
        }
    }
}

pub struct RunLookups<'a> {
    env: Environment<'a, DomainLookupConfig>,
    partial_output_config: OutputConfig,
    domain_name: Name,
    app_resolver: AppResolver,
}

impl<'a> RunLookups<'a> {
    pub async fn lookups(self) -> PartialResult<DomainLookupResult<'a>> {
        let entries = if self.env.mod_config.include_all {
            subdomain_spec::all_entries()
        } else {
            subdomain_spec::default_entries()
        };

        // Separate apex entries from subdomain entries
        let (apex_entries, subdomain_entries): (Vec<_>, Vec<_>) =
            entries.into_iter().partition(|e| e.subdomain.is_empty());

        // Build apex query: one domain, multiple record types
        let apex_record_types: Vec<RecordType> = apex_entries.iter().map(|e| e.record_type).collect();

        let apex_query = MultiQuery::multi_record(self.domain_name.clone(), apex_record_types)?;

        self.env
            .console
            .print_partial_headers("Looking up apex records.", self.app_resolver.resolvers(), &apex_query);

        info!("Looking up apex records.");
        let (apex_lookups, apex_time) = time(self.app_resolver.lookup(apex_query)).await?;
        info!("Finished apex lookups.");

        self.env
            .console
            .print_partial_results(&self.partial_output_config, &apex_lookups, apex_time)?;

        // Build category map: (subdomain, record_type) -> category
        let mut category_map: HashMap<(&str, RecordType), Category> = HashMap::new();
        for entry in subdomain_entries.iter() {
            category_map.insert((entry.subdomain, entry.record_type), entry.category);
        }

        // Group subdomain entries by record type for efficient querying
        let mut by_type: HashMap<RecordType, Vec<&SubdomainEntry>> = HashMap::new();
        for entry in subdomain_entries.iter() {
            by_type.entry(entry.record_type).or_default().push(entry);
        }

        let mut subdomain_lookups = Lookups::empty();
        let mut total_time = apex_time;

        for (record_type, entries) in by_type.iter() {
            let names: Vec<Name> = entries
                .iter()
                .map(|e: &&SubdomainEntry| {
                    Name::from_str(e.subdomain)
                        .unwrap() // Safe: subdomain specs are valid DNS labels
                        .append_domain(&self.domain_name)
                        .unwrap() // Safe: we constructed both names
                })
                .collect();

            let query = MultiQuery::new(names, vec![*record_type])?;

            self.env.console.print_partial_headers(
                &format!("Looking up {} subdomain records.", record_type),
                self.app_resolver.resolvers(),
                &query,
            );

            info!("Looking up {} subdomain records.", record_type);
            let (lookups, run_time) = time(self.app_resolver.lookup(query)).await?;
            info!("Finished {} subdomain lookups.", record_type);

            self.env
                .console
                .print_partial_results(&self.partial_output_config, &lookups, run_time)?;

            subdomain_lookups = subdomain_lookups.merge(lookups);
            total_time += run_time;
        }

        // Build a name-to-subdomain map for rendering: full query name -> subdomain label
        let mut name_to_subdomain: HashMap<Name, &str> = HashMap::new();
        for entry in subdomain_entries.iter() {
            let full_name = Name::from_str(entry.subdomain)
                .unwrap()
                .append_domain(&self.domain_name)
                .unwrap();
            name_to_subdomain.insert(full_name, entry.subdomain);
        }

        Ok(DomainLookupResult {
            env: self.env,
            domain_name: self.domain_name,
            run_time: total_time,
            apex_lookups,
            subdomain_lookups,
            category_map,
            name_to_subdomain,
        })
    }
}

pub struct DomainLookupResult<'a> {
    env: Environment<'a, DomainLookupConfig>,
    domain_name: Name,
    run_time: Duration,
    apex_lookups: Lookups,
    subdomain_lookups: Lookups,
    category_map: HashMap<(&'a str, RecordType), Category>,
    name_to_subdomain: HashMap<Name, &'a str>,
}

impl DomainLookupResult<'_> {
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
            domain: String,
            apex: Lookups,
            subdomains: Lookups,
        }
        impl SummaryFormatter for Json {
            fn output<W: Write>(&self, _: &mut W, _: &SummaryOptions) -> crate::Result<()> {
                Err(crate::Error::InternalError {
                    msg: "summary formatting is not supported for JSON output",
                })
            }
        }
        let data = Json {
            info: self.env.run_info,
            domain: self.domain_name.to_string(),
            apex: self.apex_lookups,
            subdomains: self.subdomain_lookups,
        };

        output::output(&self.env.app_config.output_config, &data)?;
        Ok(ExitStatus::Ok)
    }

    #[allow(clippy::unnecessary_wraps)]
    fn summary_output(self) -> PartialResult<ExitStatus> {
        let all_lookups = self.apex_lookups.combine(&self.subdomain_lookups);

        self.env.console.print_finished();

        if self.env.console.not_quiet() {
            self.env.console.print_statistics(&all_lookups, self.run_time);
        }

        // Print apex records using normal formatter
        self.env
            .console
            .caption(format!("Apex records for {}", Fmt::emph(&self.domain_name)));
        output::output(&self.env.app_config.output_config, &self.apex_lookups)?;

        // Collect subdomain lookups that have actual responses
        let successful_subdomain_lookups: Vec<&Lookup> = self
            .subdomain_lookups
            .iter()
            .filter(|l| l.result().is_response())
            .collect();

        if successful_subdomain_lookups.is_empty() {
            self.env.console.info("No well-known subdomain records found.");
            return Ok(ExitStatus::Ok);
        }

        // Group successful lookups by category
        let ordered_categories = [
            Category::EmailAuthentication,
            Category::EmailServices,
            Category::TlsDane,
            Category::Communication,
            Category::CalendarContacts,
            Category::Infrastructure,
            Category::ModernProtocols,
            Category::VerificationMetadata,
            Category::Legacy,
            Category::Gaming,
        ];

        // Build category -> lookups mapping
        let mut by_category: HashMap<Category, Vec<&Lookup>> = HashMap::new();
        for lookup in &successful_subdomain_lookups {
            let query_name = lookup.query().name();
            let record_type = lookup.query().record_type();
            let subdomain = self.name_to_subdomain.get(query_name).copied().unwrap_or("");
            let category = self
                .category_map
                .get(&(subdomain, record_type))
                .copied()
                .unwrap_or(Category::VerificationMetadata);
            by_category.entry(category).or_default().push(lookup);
        }

        // Print each category that has results
        for category in &ordered_categories {
            if let Some(lookups) = by_category.get(category) {
                self.env.console.caption(format!("{}", category));

                // Build a Lookups from the category's lookups and use the normal formatter
                // with show_domain_names enabled
                let cloned: Vec<Lookup> = lookups.iter().map(|l| (*l).clone()).collect();
                let category_lookups = Lookups::new(cloned);
                let opts = self.domain_names_output_config();
                output::output(&opts, &category_lookups)?;
            }
        }

        Ok(ExitStatus::Ok)
    }

    /// Creates an OutputConfig with show_domain_names always enabled
    fn domain_names_output_config(&self) -> OutputConfig {
        match &self.env.app_config.output_config {
            OutputConfig::Json { .. } => OutputConfig::Summary {
                format: SummaryFormat::new(SummaryOptions::new(
                    SummaryOptions::default().human(),
                    SummaryOptions::default().condensed(),
                    true,
                )),
            },
            OutputConfig::Summary { format } => OutputConfig::Summary {
                format: SummaryFormat::new(SummaryOptions::new(
                    format.opts().human(),
                    format.opts().condensed(),
                    true, // always show domain names for subdomains
                )),
            },
        }
    }
}
