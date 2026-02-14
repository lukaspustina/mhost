// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashSet;
use std::io::Write;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use rand::distr::Alphanumeric;
use rand::Rng;
use serde::Serialize;
use tracing::{debug, info};

use crate::app::console::Fmt;
use crate::app::modules::discover::config::DiscoverConfig;
use crate::app::modules::discover::ct_logs;
use crate::app::modules::discover::permutation;
use crate::app::modules::discover::srv_probing;
use crate::app::modules::discover::txt_mining;
use crate::app::modules::discover::wordlist::Wordlist;
use crate::app::modules::{AppModule, Environment, PartialResult, RunInfo};
use crate::app::output::summary::{SummaryFormat, SummaryFormatter, SummaryOptions};
use crate::app::output::{OutputConfig, OutputType};
use crate::app::resolver::AppResolver;
use crate::app::utils::time;
use crate::app::{output, AppConfig, ExitStatus};
use crate::resolver::lookup::Uniquify;
use crate::resolver::{Lookup, Lookups, MultiQuery};
use crate::{IntoName, Name, RecordType};

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
        let partial_output_config = Discover::create_partial_output_config(env.app_config);

        env.console
            .print_resolver_opts(app_resolver.resolver_group_opts(), app_resolver.resolver_opts());

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

// ---------------------------------------------------------------------------
// Stage 1: RequestAll (existing)
// ---------------------------------------------------------------------------

pub struct RequestAll<'a> {
    env: Environment<'a, DiscoverConfig>,
    partial_output_config: OutputConfig,
    domain_name: Name,
    app_resolver: AppResolver,
}

impl<'a> RequestAll<'a> {
    pub async fn request_all_records(self) -> PartialResult<CtLogQuery<'a>> {
        let query = MultiQuery::multi_record(
            self.domain_name.clone(),
            vec![
                RecordType::A,
                RecordType::AAAA,
                RecordType::ANY,
                RecordType::ANAME,
                RecordType::CAA,
                RecordType::CNAME,
                RecordType::HINFO,
                RecordType::HTTPS,
                RecordType::MX,
                RecordType::NAPTR,
                RecordType::NS,
                RecordType::OPENPGPKEY,
                RecordType::SRV,
                RecordType::SOA,
                RecordType::SSHFP,
                RecordType::SVCB,
                RecordType::TLSA,
                RecordType::TXT,
            ],
        )?;

        self.env
            .console
            .print_partial_headers("Requesting all record types.", self.app_resolver.resolvers(), &query);

        info!("Requesting all record types.");
        let (lookups, run_time) = time(self.app_resolver.lookup(query)).await?;
        info!("Finished Lookups.");

        self.env
            .console
            .print_partial_results(&self.partial_output_config, &lookups, run_time)?;

        Ok(CtLogQuery {
            env: self.env,
            partial_output_config: self.partial_output_config,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            run_time,
            lookups,
        })
    }
}

// ---------------------------------------------------------------------------
// Stage 2: CT Log Query (NEW)
// ---------------------------------------------------------------------------

pub struct CtLogQuery<'a> {
    env: Environment<'a, DiscoverConfig>,
    partial_output_config: OutputConfig,
    domain_name: Name,
    app_resolver: AppResolver,
    run_time: Duration,
    lookups: Lookups,
}

impl<'a> CtLogQuery<'a> {
    pub async fn ct_log_query(self) -> PartialResult<TxtRecordMining<'a>> {
        let mut ct_names = HashSet::new();

        if !self.env.mod_config.no_ct_logs {
            info!("Querying Certificate Transparency logs.");
            if self.env.console.show_partial_headers() {
                self.env.console.caption("Querying CT logs.");
            }

            let domain_str = self.domain_name.to_string();
            let domain_str = domain_str.trim_end_matches('.');

            match ct_logs::query_ct_logs(domain_str).await {
                Ok(names) => {
                    info!("CT logs returned {} unique names.", names.len());
                    if self.env.console.show_partial_headers() {
                        self.env
                            .console
                            .info(format!("CT logs returned {} unique names.", names.len()));
                    }
                    ct_names = names;
                }
                Err(e) => {
                    debug!("CT log query failed: {}", e);
                    if self.env.console.show_partial_headers() {
                        self.env.console.info(format!("CT log query failed (skipping): {}", e));
                    }
                }
            }
        } else {
            info!("Skipping CT log query (--no-ct-logs).");
            if self.env.console.show_partial_headers() {
                self.env.console.caption("Skipping CT logs (disabled).");
            }
        }

        // Resolve CT-discovered names
        let ct_lookups = if !ct_names.is_empty() {
            let names: Vec<Name> = ct_names.iter().filter_map(|n| Name::from_str(n).ok()).collect();

            if !names.is_empty() {
                match MultiQuery::new(names, vec![RecordType::A, RecordType::AAAA]) {
                    Ok(query) => {
                        self.env.console.print_partial_headers(
                            "Resolving CT log names.",
                            self.app_resolver.resolvers(),
                            &query,
                        );
                        match time(self.app_resolver.lookup(query)).await {
                            Ok((lookups, rt)) => {
                                self.env
                                    .console
                                    .print_partial_results(&self.partial_output_config, &lookups, rt)?;
                                Some(lookups)
                            }
                            Err(e) => {
                                debug!("Failed to resolve CT names: {}", e);
                                None
                            }
                        }
                    }
                    Err(_) => None,
                }
            } else {
                None
            }
        } else {
            None
        };

        let lookups = if let Some(ct) = ct_lookups {
            self.lookups.merge(ct)
        } else {
            self.lookups
        };

        Ok(TxtRecordMining {
            env: self.env,
            partial_output_config: self.partial_output_config,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            run_time: self.run_time,
            lookups,
        })
    }
}

// ---------------------------------------------------------------------------
// Stage 3: TXT Record Mining (NEW)
// ---------------------------------------------------------------------------

pub struct TxtRecordMining<'a> {
    env: Environment<'a, DiscoverConfig>,
    partial_output_config: OutputConfig,
    domain_name: Name,
    app_resolver: AppResolver,
    run_time: Duration,
    lookups: Lookups,
}

impl<'a> TxtRecordMining<'a> {
    pub async fn txt_record_mining(self) -> PartialResult<SrvServiceProbing<'a>> {
        info!("Mining TXT records for domains.");

        // Extract domains from existing SPF and DMARC TXT records
        let txt_records = self.lookups.txt();
        let spf_domains = txt_mining::extract_spf_domains(&txt_records);
        let dmarc_domains = txt_mining::extract_dmarc_domains(&txt_records);

        let mined_domains: HashSet<String> = spf_domains.union(&dmarc_domains).cloned().collect();
        info!("Mined {} domains from TXT records.", mined_domains.len());

        // Query well-known TXT subdomains
        let well_known = txt_mining::well_known_txt_subdomains();
        let subdomain_names: Vec<Name> = well_known
            .iter()
            .filter_map(|sub| {
                Name::from_str(sub)
                    .ok()
                    .and_then(|n| n.append_domain(&self.domain_name).ok())
            })
            .collect();

        let mut extra_lookups = Vec::new();

        if !subdomain_names.is_empty() {
            if let Ok(query) = MultiQuery::new(subdomain_names, vec![RecordType::TXT]) {
                self.env
                    .console
                    .print_partial_headers("TXT record mining.", self.app_resolver.resolvers(), &query);

                match time(self.app_resolver.lookup(query)).await {
                    Ok((lookups, run_time)) => {
                        self.env
                            .console
                            .print_partial_results(&self.partial_output_config, &lookups, run_time)?;
                        extra_lookups.push(lookups);
                    }
                    Err(e) => debug!("TXT subdomain lookups failed: {}", e),
                }
            }
        }

        // Resolve mined domains
        if !mined_domains.is_empty() {
            let names: Vec<Name> = mined_domains.iter().filter_map(|n| Name::from_str(n).ok()).collect();
            if !names.is_empty() {
                if let Ok(query) = MultiQuery::new(names, vec![RecordType::A, RecordType::AAAA]) {
                    match time(self.app_resolver.lookup(query)).await {
                        Ok((lookups, _)) => extra_lookups.push(lookups),
                        Err(e) => debug!("Failed to resolve mined TXT domains: {}", e),
                    }
                }
            }
        }

        let mut lookups = self.lookups;
        for extra in extra_lookups {
            lookups = lookups.merge(extra);
        }

        Ok(SrvServiceProbing {
            env: self.env,
            partial_output_config: self.partial_output_config,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            run_time: self.run_time,
            lookups,
        })
    }
}

// ---------------------------------------------------------------------------
// Stage 4: SRV Service Probing (NEW)
// ---------------------------------------------------------------------------

pub struct SrvServiceProbing<'a> {
    env: Environment<'a, DiscoverConfig>,
    partial_output_config: OutputConfig,
    domain_name: Name,
    app_resolver: AppResolver,
    run_time: Duration,
    lookups: Lookups,
}

impl<'a> SrvServiceProbing<'a> {
    pub async fn srv_service_probing(self) -> PartialResult<WildcardCheck<'a>> {
        info!("Probing well-known SRV services.");

        let probes = srv_probing::well_known_srv_probes();
        let srv_names: Vec<Name> = probes
            .iter()
            .filter_map(|probe| {
                let sub = probe.to_subdomain();
                Name::from_str(&sub)
                    .ok()
                    .and_then(|n| n.append_domain(&self.domain_name).ok())
            })
            .collect();

        let lookups = if !srv_names.is_empty() {
            if let Ok(query) = MultiQuery::new(srv_names, vec![RecordType::SRV]) {
                self.env
                    .console
                    .print_partial_headers("SRV service probing.", self.app_resolver.resolvers(), &query);

                match time(self.app_resolver.lookup(query)).await {
                    Ok((srv_lookups, run_time)) => {
                        self.env
                            .console
                            .print_partial_results(&self.partial_output_config, &srv_lookups, run_time)?;
                        self.lookups.merge(srv_lookups)
                    }
                    Err(e) => {
                        debug!("SRV probing failed: {}", e);
                        self.lookups
                    }
                }
            } else {
                self.lookups
            }
        } else {
            self.lookups
        };

        Ok(WildcardCheck {
            env: self.env,
            partial_output_config: self.partial_output_config,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            run_time: self.run_time,
            lookups,
        })
    }
}

// ---------------------------------------------------------------------------
// Stage 5: WildcardCheck (existing)
// ---------------------------------------------------------------------------

pub struct WildcardCheck<'a> {
    env: Environment<'a, DiscoverConfig>,
    partial_output_config: OutputConfig,
    domain_name: Name,
    app_resolver: AppResolver,
    run_time: Duration,
    lookups: Lookups,
}

impl<'a> WildcardCheck<'a> {
    pub async fn check_wildcard_resolution(self) -> PartialResult<AxfrAttempt<'a>> {
        let rnd_names =
            WildcardCheck::rnd_names(self.env.mod_config.rnd_names_number, self.env.mod_config.rnd_names_len)
                .into_iter()
                .map(|x| Name::from_str(&x).unwrap().append_domain(&self.domain_name).unwrap()); // Safe unwraps, we constructed the names
        let query = MultiQuery::new(rnd_names, vec![RecordType::A, RecordType::AAAA])?;

        self.env
            .console
            .print_partial_headers("Checking wildcard resolution.", self.app_resolver.resolvers(), &query);

        info!("Checking wildcard resolution.");
        let (lookups, run_time) = time(self.app_resolver.lookup(query)).await?;
        info!("Finished Lookups.");

        self.env
            .console
            .print_partial_results(&self.partial_output_config, &lookups, run_time)?;

        Ok(AxfrAttempt {
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
        let mut rng = rand::rng();
        (0..number)
            .map(|_| (&mut rng).sample_iter(Alphanumeric).take(len).map(char::from).collect())
            .inspect(|x| debug!("Generated random domain name: '{}'", x))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Stage 6: AXFR Attempt (NEW)
// ---------------------------------------------------------------------------

pub struct AxfrAttempt<'a> {
    env: Environment<'a, DiscoverConfig>,
    partial_output_config: OutputConfig,
    domain_name: Name,
    app_resolver: AppResolver,
    run_time: Duration,
    wildcard_lookups: Option<Lookups>,
    lookups: Lookups,
}

impl<'a> AxfrAttempt<'a> {
    pub async fn axfr_attempt(self) -> PartialResult<NsecWalking<'a>> {
        info!("Attempting zone transfer (AXFR) - best effort.");
        if self.env.console.show_partial_headers() {
            self.env.console.caption("Attempting zone transfer (AXFR).");
        }

        // Get NS records for the domain and try AXFR against each
        let ns_names = self.lookups.ns();
        if ns_names.is_empty() {
            info!("No NS records found, skipping AXFR.");
            if self.env.console.show_partial_headers() {
                self.env.console.info("No NS records found, skipping AXFR.");
            }
        } else {
            // Resolve NS names to IP addresses
            let ns_name_list: Vec<Name> = ns_names.into_iter().cloned().collect();
            if let Ok(query) = MultiQuery::new(ns_name_list, vec![RecordType::A]) {
                match time(self.app_resolver.lookup(query)).await {
                    Ok((ns_lookups, _)) => {
                        let ns_ips = ns_lookups.ips();
                        info!("Resolved {} NS IP addresses for AXFR attempt.", ns_ips.len());

                        for ip in ns_ips.iter().take(3) {
                            info!("Trying AXFR against {}", ip);
                            // Create a TCP resolver pointed at this NS and try AXFR
                            let ns_spec = format!("tcp:{}:53", ip);
                            let ns_config = match crate::nameserver::NameServerConfig::from_str(&ns_spec) {
                                Ok(c) => c,
                                Err(_) => continue,
                            };
                            let resolver_config = crate::resolver::ResolverConfig::from(ns_config);

                            match AppResolver::from_configs(vec![resolver_config], self.env.app_config).await {
                                Ok(axfr_resolver) => {
                                    if let Ok(query) =
                                        MultiQuery::multi_record(self.domain_name.clone(), vec![RecordType::AXFR])
                                    {
                                        match tokio::time::timeout(Duration::from_secs(5), axfr_resolver.lookup(query))
                                            .await
                                        {
                                            Ok(Ok(axfr_lookups)) if axfr_lookups.has_records() => {
                                                info!("AXFR succeeded against {}!", ip);
                                                if self.env.console.show_partial_headers() {
                                                    self.env.console.info(format!(
                                                        "AXFR succeeded against {} ({} records).",
                                                        ip,
                                                        axfr_lookups.records().len()
                                                    ));
                                                }
                                                // We got data - merge and move on
                                                let lookups = self.lookups.merge(axfr_lookups);
                                                return Ok(NsecWalking {
                                                    env: self.env,
                                                    partial_output_config: self.partial_output_config,
                                                    domain_name: self.domain_name,
                                                    app_resolver: self.app_resolver,
                                                    run_time: self.run_time,
                                                    wildcard_lookups: self.wildcard_lookups,
                                                    lookups,
                                                });
                                            }
                                            Ok(Ok(_)) => {
                                                debug!("AXFR returned no records from {}", ip);
                                            }
                                            Ok(Err(e)) => {
                                                debug!("AXFR failed against {}: {}", ip, e);
                                            }
                                            Err(_) => {
                                                debug!("AXFR timed out against {}", ip);
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    debug!("Failed to create resolver for AXFR against {}: {}", ip, e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Failed to resolve NS addresses for AXFR: {}", e);
                    }
                }
            }

            if self.env.console.show_partial_headers() {
                self.env.console.info("AXFR not available (expected for most zones).");
            }
        }

        Ok(NsecWalking {
            env: self.env,
            partial_output_config: self.partial_output_config,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            run_time: self.run_time,
            wildcard_lookups: self.wildcard_lookups,
            lookups: self.lookups,
        })
    }
}

// ---------------------------------------------------------------------------
// Stage 7: NSEC Walking (NEW)
// ---------------------------------------------------------------------------

pub struct NsecWalking<'a> {
    env: Environment<'a, DiscoverConfig>,
    partial_output_config: OutputConfig,
    domain_name: Name,
    app_resolver: AppResolver,
    run_time: Duration,
    wildcard_lookups: Option<Lookups>,
    lookups: Lookups,
}

impl<'a> NsecWalking<'a> {
    pub async fn nsec_walking(self) -> PartialResult<WordlistLookups<'a>> {
        info!("Attempting NSEC walking - best effort.");
        if self.env.console.show_partial_headers() {
            self.env.console.caption("Attempting NSEC walking.");
        }

        // Query DNSSEC records for the domain to see if NSEC is available
        if let Ok(query) = MultiQuery::multi_record(self.domain_name.clone(), vec![RecordType::DNSSEC]) {
            match time(self.app_resolver.lookup(query)).await {
                Ok((dnssec_lookups, _)) => {
                    let dnssec_records = dnssec_lookups.dnssec();
                    if dnssec_records.is_empty() {
                        info!("No DNSSEC records found, skipping NSEC walking.");
                        if self.env.console.show_partial_headers() {
                            self.env.console.info("No DNSSEC/NSEC records found.");
                        }
                    } else {
                        info!(
                            "Found {} DNSSEC records. NSEC walking is fragile and may not yield results.",
                            dnssec_records.len()
                        );
                        if self.env.console.show_partial_headers() {
                            self.env.console.info(format!(
                                "Found {} DNSSEC records (NSEC walking is best-effort).",
                                dnssec_records.len()
                            ));
                        }
                        // NSEC walking requires parsing the "next name" from NSEC record data.
                        // The description string format is fragile and implementation-specific.
                        // For now, we log that we found DNSSEC but don't attempt full walking
                        // since the hickory resolver doesn't expose raw NSEC next-name fields
                        // in a structured way through our abstraction layer.
                    }
                }
                Err(e) => {
                    debug!("DNSSEC query failed: {}", e);
                    if self.env.console.show_partial_headers() {
                        self.env.console.info("DNSSEC query failed, skipping NSEC walking.");
                    }
                }
            }
        }

        Ok(WordlistLookups {
            env: self.env,
            partial_output_config: self.partial_output_config,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            run_time: self.run_time,
            wildcard_lookups: self.wildcard_lookups,
            lookups: self.lookups,
        })
    }
}

// ---------------------------------------------------------------------------
// Stage 8: WordlistLookups (existing)
// ---------------------------------------------------------------------------

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
    pub async fn wordlist_lookups(self) -> PartialResult<SubdomainPermutation<'a>> {
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
            .print_partial_headers("Wordlist lookups.", self.app_resolver.resolvers(), &query);

        info!("Wordlist lookups.");
        let (lookups, run_time) = time(self.app_resolver.lookup(query)).await?;
        info!("Finished Lookups.");

        // Filter wildcard responses
        let lookups = filter_wildcard_responses(&self.wildcard_lookups, lookups);

        self.env
            .console
            .print_partial_results(&self.partial_output_config, &lookups, run_time)?;

        // Merge lookups from this step with previous step
        let lookups = lookups.merge(self.lookups);

        Ok(SubdomainPermutation {
            env: self.env,
            partial_output_config: self.partial_output_config,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            run_time: self.run_time + run_time,
            wildcard_lookups: self.wildcard_lookups,
            lookups,
        })
    }

    async fn load_wordlist(&self, append_domain_name: &Name) -> Result<Vec<Name>> {
        let wordlist: Vec<_> = if let Some(ref path) = self.env.mod_config.wordlist_file_path {
            Wordlist::from_file(path).await?
        } else {
            Wordlist::default()?
        }
        .into_iter()
        .map(|x| x.append_domain(append_domain_name))
        .collect::<std::result::Result<Vec<_>, _>>()?;
        debug!("Loaded wordlist with {} words", wordlist.len());

        Ok(wordlist)
    }
}

// ---------------------------------------------------------------------------
// Stage 9: Subdomain Permutation (NEW)
// ---------------------------------------------------------------------------

pub struct SubdomainPermutation<'a> {
    env: Environment<'a, DiscoverConfig>,
    partial_output_config: OutputConfig,
    domain_name: Name,
    app_resolver: AppResolver,
    run_time: Duration,
    wildcard_lookups: Option<Lookups>,
    lookups: Lookups,
}

impl<'a> SubdomainPermutation<'a> {
    pub async fn subdomain_permutation(self) -> PartialResult<RecursiveDepthDiscovery<'a>> {
        info!("Generating subdomain permutations.");

        // Extract first-level labels from discovered subdomains
        let discovered_labels = self.extract_first_labels();

        if discovered_labels.is_empty() {
            info!("No subdomain labels to permute.");
            return Ok(RecursiveDepthDiscovery {
                env: self.env,
                partial_output_config: self.partial_output_config,
                domain_name: self.domain_name,
                app_resolver: self.app_resolver,
                run_time: self.run_time,
                wildcard_lookups: self.wildcard_lookups,
                lookups: self.lookups,
            });
        }

        let permutations = permutation::generate_permutations(&discovered_labels);
        info!("Generated {} permutations.", permutations.len());

        if permutations.is_empty() {
            return Ok(RecursiveDepthDiscovery {
                env: self.env,
                partial_output_config: self.partial_output_config,
                domain_name: self.domain_name,
                app_resolver: self.app_resolver,
                run_time: self.run_time,
                wildcard_lookups: self.wildcard_lookups,
                lookups: self.lookups,
            });
        }

        let perm_names: Vec<Name> = permutations
            .iter()
            .filter_map(|label| {
                Name::from_str(label)
                    .ok()
                    .and_then(|n| n.append_domain(&self.domain_name).ok())
            })
            .collect();

        let lookups = if !perm_names.is_empty() {
            if let Ok(query) = MultiQuery::new(perm_names, vec![RecordType::A, RecordType::AAAA]) {
                self.env.console.print_partial_headers(
                    "Subdomain permutation lookups.",
                    self.app_resolver.resolvers(),
                    &query,
                );

                match time(self.app_resolver.lookup(query)).await {
                    Ok((perm_lookups, run_time)) => {
                        let perm_lookups = filter_wildcard_responses(&self.wildcard_lookups, perm_lookups);
                        self.env
                            .console
                            .print_partial_results(&self.partial_output_config, &perm_lookups, run_time)?;
                        self.lookups.merge(perm_lookups)
                    }
                    Err(e) => {
                        debug!("Permutation lookups failed: {}", e);
                        self.lookups
                    }
                }
            } else {
                self.lookups
            }
        } else {
            self.lookups
        };

        Ok(RecursiveDepthDiscovery {
            env: self.env,
            partial_output_config: self.partial_output_config,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            run_time: self.run_time,
            wildcard_lookups: self.wildcard_lookups,
            lookups,
        })
    }

    fn extract_first_labels(&self) -> HashSet<String> {
        self.lookups
            .iter()
            .filter(|l| l.result().is_response())
            .map(|l| l.query().name())
            .filter(|name| self.domain_name.zone_of(name))
            .filter_map(|name| {
                let domain_labels = self.domain_name.num_labels();
                let name_labels = name.num_labels();
                if name_labels > domain_labels {
                    // Get the first (leftmost) label
                    name.iter()
                        .next()
                        .map(|label| String::from_utf8_lossy(label).to_lowercase())
                } else {
                    None
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Stage 10: Recursive Depth Discovery (NEW)
// ---------------------------------------------------------------------------

pub struct RecursiveDepthDiscovery<'a> {
    env: Environment<'a, DiscoverConfig>,
    partial_output_config: OutputConfig,
    domain_name: Name,
    app_resolver: AppResolver,
    run_time: Duration,
    wildcard_lookups: Option<Lookups>,
    lookups: Lookups,
}

impl<'a> RecursiveDepthDiscovery<'a> {
    pub async fn recursive_depth_discovery(self) -> PartialResult<ReverseDnsLookups<'a>> {
        let depth = self.env.mod_config.depth;

        if depth == 0 {
            info!("Recursive depth discovery disabled (depth=0).");
            return Ok(ReverseDnsLookups {
                env: self.env,
                partial_output_config: self.partial_output_config,
                domain_name: self.domain_name,
                app_resolver: self.app_resolver,
                run_time: self.run_time,
                wildcard_lookups: self.wildcard_lookups,
                lookups: self.lookups,
            });
        }

        info!("Starting recursive depth discovery (depth={}).", depth);
        if self.env.console.show_partial_headers() {
            self.env
                .console
                .caption(format!("Recursive depth discovery (depth={}).", depth));
        }

        // Find subdomains that are themselves zone roots we can explore deeper
        let subdomains: Vec<Name> = self
            .lookups
            .iter()
            .filter(|l| l.result().is_response())
            .map(|l| l.query().name().clone())
            .filter(|name| self.domain_name.zone_of(name) && name != &self.domain_name)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        if subdomains.is_empty() {
            info!("No subdomains found for recursive discovery.");
            return Ok(ReverseDnsLookups {
                env: self.env,
                partial_output_config: self.partial_output_config,
                domain_name: self.domain_name,
                app_resolver: self.app_resolver,
                run_time: self.run_time,
                wildcard_lookups: self.wildcard_lookups,
                lookups: self.lookups,
            });
        }

        // Use a small subset of the default wordlist for recursive discovery
        let mini_wordlist = match Wordlist::default() {
            Ok(wl) => wl.into_iter().take(20).collect::<Vec<_>>(),
            Err(_) => {
                return Ok(ReverseDnsLookups {
                    env: self.env,
                    partial_output_config: self.partial_output_config,
                    domain_name: self.domain_name,
                    app_resolver: self.app_resolver,
                    run_time: self.run_time,
                    wildcard_lookups: self.wildcard_lookups,
                    lookups: self.lookups,
                })
            }
        };

        let mut lookups = self.lookups;

        for current_depth in 1..=depth {
            info!("Recursive discovery depth {}/{}.", current_depth, depth);

            let names: Vec<Name> = subdomains
                .iter()
                .flat_map(|subdomain| {
                    mini_wordlist
                        .iter()
                        .filter_map(|word| word.clone().append_domain(subdomain).ok())
                })
                .collect();

            if names.is_empty() {
                break;
            }

            if let Ok(query) = MultiQuery::new(names, vec![RecordType::A, RecordType::AAAA]) {
                self.env.console.print_partial_headers(
                    &format!("Recursive discovery depth {}/{}.", current_depth, depth),
                    self.app_resolver.resolvers(),
                    &query,
                );

                match time(self.app_resolver.lookup(query)).await {
                    Ok((depth_lookups, run_time)) => {
                        let depth_lookups = filter_wildcard_responses(&self.wildcard_lookups, depth_lookups);
                        self.env.console.print_partial_results(
                            &self.partial_output_config,
                            &depth_lookups,
                            run_time,
                        )?;
                        lookups = lookups.merge(depth_lookups);
                    }
                    Err(e) => {
                        debug!("Recursive discovery at depth {} failed: {}", current_depth, e);
                        break;
                    }
                }
            }
        }

        Ok(ReverseDnsLookups {
            env: self.env,
            partial_output_config: self.partial_output_config,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            run_time: self.run_time,
            wildcard_lookups: self.wildcard_lookups,
            lookups,
        })
    }
}

// ---------------------------------------------------------------------------
// Stage 11: Reverse DNS Lookups (NEW)
// ---------------------------------------------------------------------------

pub struct ReverseDnsLookups<'a> {
    env: Environment<'a, DiscoverConfig>,
    partial_output_config: OutputConfig,
    domain_name: Name,
    app_resolver: AppResolver,
    run_time: Duration,
    wildcard_lookups: Option<Lookups>,
    lookups: Lookups,
}

impl<'a> ReverseDnsLookups<'a> {
    pub async fn reverse_dns_lookups(self) -> PartialResult<OutputDiscoverResult<'a>> {
        info!("Performing reverse DNS lookups on discovered IPs.");

        let ips: HashSet<IpAddr> = self.lookups.ips().into_iter().collect();

        let lookups = if !ips.is_empty() {
            let ptr_names: Vec<Name> = ips.iter().filter_map(|ip| ip.into_name().ok()).collect();

            if !ptr_names.is_empty() {
                if let Ok(query) = MultiQuery::new(ptr_names, vec![RecordType::PTR]) {
                    self.env.console.print_partial_headers(
                        "Reverse DNS lookups.",
                        self.app_resolver.resolvers(),
                        &query,
                    );

                    match time(self.app_resolver.lookup(query)).await {
                        Ok((ptr_lookups, run_time)) => {
                            self.env.console.print_partial_results(
                                &self.partial_output_config,
                                &ptr_lookups,
                                run_time,
                            )?;
                            self.lookups.merge(ptr_lookups)
                        }
                        Err(e) => {
                            debug!("Reverse DNS lookups failed: {}", e);
                            self.lookups
                        }
                    }
                } else {
                    self.lookups
                }
            } else {
                self.lookups
            }
        } else {
            self.lookups
        };

        Ok(OutputDiscoverResult {
            env: self.env,
            domain_name: self.domain_name,
            run_time: self.run_time,
            wildcard_lookups: self.wildcard_lookups,
            lookups,
        })
    }
}

// ---------------------------------------------------------------------------
// Stage 12: Output (existing)
// ---------------------------------------------------------------------------

pub struct OutputDiscoverResult<'a> {
    env: Environment<'a, DiscoverConfig>,
    domain_name: Name,
    run_time: Duration,
    wildcard_lookups: Option<Lookups>,
    lookups: Lookups,
}

impl OutputDiscoverResult<'_> {
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

    #[allow(clippy::unnecessary_wraps)]
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
            .filter(|name| !Self::is_reverse_dns_name(name))
            .unique()
            .to_owned()
            .into_iter()
            .collect()
    }

    fn is_reverse_dns_name(name: &Name) -> bool {
        let s = name.to_ascii();
        s.ends_with(".in-addr.arpa.") || s.ends_with(".ip6.arpa.")
    }

    fn print_fancy_name_by_domain(&self, name: &Name, domain_name: &Name) {
        if domain_name.zone_of(name) {
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

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Filter lookups that match wildcard resolutions.
fn filter_wildcard_responses(wildcard_lookups: &Option<Lookups>, lookups: Lookups) -> Lookups {
    if let Some(ref wildcards) = wildcard_lookups {
        let wildcard_records = wildcards.records();
        let wildcard_resolutions = wildcard_records.iter().unique().iter().map(|x| x.data()).collect();

        let lookups = lookups
            .into_iter()
            .filter(|lookup: &Lookup| {
                let records = lookup.records();
                let set: HashSet<_> = records.iter().unique().iter().map(|x| x.data()).collect();
                set.is_disjoint(&wildcard_resolutions)
            })
            .collect();
        Lookups::new(lookups)
    } else {
        lookups
    }
}
