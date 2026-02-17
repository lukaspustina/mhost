// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;

use anyhow::Context;
use serde::Serialize;
use tracing::{debug, info, warn};

use crate::app::modules::propagation::config::PropagationConfig;
use crate::app::modules::{AppModule, Environment, PartialResult, RunInfo};
use crate::app::output::summary::{SummaryFormatter, SummaryOptions};
use crate::app::output::OutputType;
use crate::app::resolver::AppResolver;
use crate::app::utils::time;
use crate::app::{output, AppConfig, ExitStatus};
use crate::nameserver::{predefined, NameServerConfig};
use crate::resolver::lookup::{LookupResult, Uniquify};
use crate::resolver::{Lookups, MultiQuery, ResolverConfig};
use crate::resources::Record;
use crate::RecordType;

pub struct Propagation {}

impl AppModule<PropagationConfig> for Propagation {}

impl Propagation {
    pub async fn init<'a>(
        app_config: &'a AppConfig,
        config: &'a PropagationConfig,
    ) -> PartialResult<AuthoritativeDiscovery<'a>> {
        let env = Self::init_env(app_config, config)?;

        let domain_name = env.name_builder.from_str(&config.domain_name)?;

        // Build query types: user-requested types + SOA for serial comparison
        let mut query_types = config.record_types.clone();
        if !query_types.contains(&RecordType::SOA) {
            query_types.push(RecordType::SOA);
        }

        let query =
            MultiQuery::multi_record(domain_name.clone(), query_types.clone()).context("Failed to build query")?;
        debug!("Querying: {:?}", query);

        let configs: Vec<ResolverConfig> = predefined::propagation_nameserver_configs()
            .into_iter()
            .filter(|ns| app_config.ip_allowed(ns.ip_addr()))
            .map(ResolverConfig::from)
            .collect();

        let app_resolver = AppResolver::from_configs(configs, app_config).await?;

        env.console
            .print_resolver_opts(app_resolver.resolver_group_opts(), app_resolver.resolver_opts());

        Ok(AuthoritativeDiscovery {
            env,
            domain_name,
            query_types,
            query,
            app_resolver,
        })
    }
}

// ---------------------------------------------------------------------------
// Step 1: Authoritative NS discovery
// ---------------------------------------------------------------------------

pub struct AuthoritativeDiscovery<'a> {
    env: Environment<'a, PropagationConfig>,
    domain_name: hickory_resolver::Name,
    query_types: Vec<RecordType>,
    query: MultiQuery,
    app_resolver: AppResolver,
}

impl<'a> AuthoritativeDiscovery<'a> {
    pub async fn discover(self) -> PartialResult<DnsLookups<'a>> {
        if self.env.console.not_quiet() {
            self.env.console.info("Discovering authoritative nameservers.");
        }
        info!("Discovering authoritative nameservers");

        let auth_info = self.discover_authoritative().await;

        Ok(DnsLookups {
            env: self.env,
            query: self.query,
            app_resolver: self.app_resolver,
            auth_info,
        })
    }

    async fn discover_authoritative(&self) -> AuthoritativeInfo {
        // Step 1: Query NS records for the domain
        let ns_query = match MultiQuery::single(self.domain_name.clone(), RecordType::NS) {
            Ok(q) => q,
            Err(e) => {
                warn!("Failed to build NS query: {}", e);
                return AuthoritativeInfo::empty();
            }
        };

        let ns_lookups = match self.app_resolver.lookup(ns_query).await {
            Ok(l) => l,
            Err(e) => {
                warn!("NS lookup failed: {}", e);
                return AuthoritativeInfo::empty();
            }
        };

        let ns_names: Vec<hickory_resolver::Name> = ns_lookups.ns().unique().to_owned().into_iter().collect();
        if ns_names.is_empty() {
            info!("No NS records found for authoritative discovery");
            return AuthoritativeInfo::empty();
        }
        info!("Found {} NS records", ns_names.len());

        // Step 2: Resolve NS hostnames to IPs
        let addr_query = match MultiQuery::new(ns_names.clone(), vec![RecordType::A, RecordType::AAAA]) {
            Ok(q) => q,
            Err(e) => {
                warn!("Failed to build NS address query: {}", e);
                return AuthoritativeInfo::empty();
            }
        };

        let addr_lookups = match self.app_resolver.lookup(addr_query).await {
            Ok(l) => l,
            Err(e) => {
                warn!("NS address resolution failed: {}", e);
                return AuthoritativeInfo::empty();
            }
        };

        // Build mapping: NS name → IPs
        let mut ns_name_to_ips: HashMap<String, Vec<IpAddr>> = HashMap::new();
        for lookup in addr_lookups.iter() {
            let ns_name = lookup.query().name.to_string();
            if let LookupResult::Response(response) = lookup.result() {
                for record in response.records() {
                    if let Some(ip) = record.data().a() {
                        ns_name_to_ips.entry(ns_name.clone()).or_default().push(IpAddr::V4(*ip));
                    }
                    if let Some(ip) = record.data().aaaa() {
                        ns_name_to_ips.entry(ns_name.clone()).or_default().push(IpAddr::V6(*ip));
                    }
                }
            }
        }

        // Build (ns_name, ip) pairs and IP→ns_name reverse map
        let mut ip_to_ns_name: HashMap<String, String> = HashMap::new();
        let mut auth_configs = Vec::new();
        for (ns_name, ips) in &ns_name_to_ips {
            for ip in ips {
                let ip_str = ip.to_string();
                ip_to_ns_name.insert(ip_str, ns_name.clone());
                auth_configs.push(NameServerConfig::udp((*ip, 53)));
            }
        }

        if auth_configs.is_empty() {
            warn!("Could not resolve any NS server addresses");
            return AuthoritativeInfo::empty();
        }

        // Step 3: Query each authoritative NS for SOA + user types
        let auth_resolver_configs = auth_configs.into_iter().map(ResolverConfig::new);
        let auth_resolver = match AppResolver::from_configs(auth_resolver_configs, self.env.app_config).await {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to create authoritative resolvers: {}", e);
                return AuthoritativeInfo::empty();
            }
        };

        let auth_query = match MultiQuery::multi_record(self.domain_name.clone(), self.query_types.clone()) {
            Ok(q) => q,
            Err(e) => {
                warn!("Failed to build authoritative query: {}", e);
                return AuthoritativeInfo::empty();
            }
        };

        let auth_lookups = match auth_resolver.lookup(auth_query).await {
            Ok(l) => l,
            Err(e) => {
                warn!("Authoritative lookups failed: {}", e);
                return AuthoritativeInfo::empty();
            }
        };

        // Step 4: Extract per-NS results
        let user_record_types = &self.env.mod_config.record_types;
        let mut ns_results: HashMap<String, AuthoritativeNsInfo> = HashMap::new();

        for lookup in auth_lookups.iter() {
            let ip_str = nameserver_ip(lookup.name_server()).to_string();
            let ns_name = ip_to_ns_name
                .get(&ip_str)
                .cloned()
                .unwrap_or_else(|| "Unknown".to_string());

            let entry = ns_results.entry(ip_str.clone()).or_insert_with(|| AuthoritativeNsInfo {
                ns_name,
                ip: ip_str,
                serial: None,
                records: Vec::new(),
                error: None,
            });

            match lookup.result() {
                LookupResult::Response(response) => {
                    for record in response.records() {
                        if record.record_type() == RecordType::SOA {
                            if let Some(soa) = record.data().soa() {
                                entry.serial = Some(soa.serial());
                            }
                        }
                        if user_record_types.contains(&record.record_type()) && !entry.records.contains(record) {
                            entry.records.push(record.clone());
                        }
                    }
                }
                LookupResult::NxDomain(_) => {}
                LookupResult::Error(e) => {
                    entry.error = Some(format!("{}", e));
                }
            }
        }

        // Determine authoritative serial (highest serial seen)
        let authoritative_serial = ns_results.values().filter_map(|info| info.serial).max();

        // Extract SOA details from first available SOA
        let soa_details = auth_lookups.soa().first().map(|soa| SoaDetails {
            refresh: soa.refresh(),
            retry: soa.retry(),
            expire: soa.expire(),
            minimum: soa.minimum(),
        });

        let authoritative_ns: Vec<AuthoritativeNsInfo> = ns_results.into_values().collect();
        info!(
            "Discovered {} authoritative NSes, serial={:?}",
            authoritative_ns.len(),
            authoritative_serial
        );

        AuthoritativeInfo {
            authoritative_serial,
            authoritative_ns,
            soa_details,
        }
    }
}

/// Intermediate container for authoritative discovery results
struct AuthoritativeInfo {
    authoritative_serial: Option<u32>,
    authoritative_ns: Vec<AuthoritativeNsInfo>,
    soa_details: Option<SoaDetails>,
}

impl AuthoritativeInfo {
    fn empty() -> Self {
        AuthoritativeInfo {
            authoritative_serial: None,
            authoritative_ns: Vec::new(),
            soa_details: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Step 2: Recursive resolver lookups
// ---------------------------------------------------------------------------

pub struct DnsLookups<'a> {
    env: Environment<'a, PropagationConfig>,
    query: MultiQuery,
    app_resolver: AppResolver,
    auth_info: AuthoritativeInfo,
}

impl<'a> DnsLookups<'a> {
    pub async fn lookups(self) -> PartialResult<PropagationCompute<'a>> {
        self.env.console.print_partial_headers(
            "Running propagation lookups.",
            self.app_resolver.resolvers(),
            &self.query,
        );
        info!("Running propagation lookups");
        let (lookups, run_time) = time(self.app_resolver.lookup(self.query)).await?;
        info!("Finished propagation lookups in {:?}.", run_time);

        if self.env.console.not_quiet() {
            self.env
                .console
                .info(format!("Received {} lookups in {:.1?}.", lookups.len(), run_time,));
        }

        Ok(PropagationCompute {
            env: self.env,
            lookups,
            auth_info: self.auth_info,
        })
    }
}

// ---------------------------------------------------------------------------
// Step 3: Compute propagation status
// ---------------------------------------------------------------------------

pub struct PropagationCompute<'a> {
    env: Environment<'a, PropagationConfig>,
    lookups: Lookups,
    auth_info: AuthoritativeInfo,
}

impl<'a> PropagationCompute<'a> {
    pub fn compute(self) -> PropagationOutput<'a> {
        let user_record_types = self.env.mod_config.record_types.clone();
        let results = compute_propagation(
            &self.env.mod_config.domain_name,
            &user_record_types,
            &self.lookups,
            self.auth_info,
        );

        PropagationOutput { env: self.env, results }
    }
}

fn nameserver_name(ns: &NameServerConfig) -> String {
    match ns {
        NameServerConfig::Udp { name, .. }
        | NameServerConfig::Tcp { name, .. }
        | NameServerConfig::Tls { name, .. }
        | NameServerConfig::Https { name, .. } => name.clone().unwrap_or_else(|| "Unknown".to_string()),
    }
}

fn nameserver_ip(ns: &NameServerConfig) -> &IpAddr {
    match ns {
        NameServerConfig::Udp { ip_addr, .. }
        | NameServerConfig::Tcp { ip_addr, .. }
        | NameServerConfig::Tls { ip_addr, .. }
        | NameServerConfig::Https { ip_addr, .. } => ip_addr,
    }
}

/// Core computation: group recursive resolver results by SOA serial.
fn compute_propagation(
    domain_name: &str,
    user_record_types: &[RecordType],
    lookups: &Lookups,
    auth_info: AuthoritativeInfo,
) -> PropagationResults {
    // Collect per-server data from recursive resolver lookups
    let mut server_data: HashMap<String, ServerData> = HashMap::new();

    for lookup in lookups.iter() {
        let ip_str = nameserver_ip(lookup.name_server()).to_string();
        let name = nameserver_name(lookup.name_server());

        let entry = server_data.entry(ip_str.clone()).or_insert_with(|| ServerData {
            info: ResolverInfo { name, ip: ip_str },
            serial: None,
            records: Vec::new(),
            has_error: false,
        });

        match lookup.result() {
            LookupResult::Response(response) => {
                for record in response.records() {
                    if record.record_type() == RecordType::SOA {
                        if let Some(soa) = record.data().soa() {
                            entry.serial = Some(soa.serial());
                        }
                    }
                    if user_record_types.contains(&record.record_type()) && !entry.records.contains(record) {
                        entry.records.push(record.clone());
                    }
                }
            }
            LookupResult::NxDomain(_) => {}
            LookupResult::Error(_) => {
                entry.has_error = true;
            }
        }
    }

    // Separate unreachable servers (no serial, only errors) — they should not
    // count towards propagation statistics.
    let mut reachable = HashMap::new();
    let mut unreachable = Vec::new();
    for (key, sd) in server_data {
        if sd.serial.is_none() && sd.has_error {
            unreachable.push(sd);
        } else {
            reachable.insert(key, sd);
        }
    }
    let server_data = reachable;
    let total_resolvers = server_data.len();

    // Determine authoritative serial; fall back to highest recursive serial
    let authoritative_serial = auth_info
        .authoritative_serial
        .or_else(|| server_data.values().filter_map(|sd| sd.serial).max());

    // Also extract SOA details from recursive lookups if not from authoritative
    let soa_details = auth_info.soa_details.or_else(|| {
        lookups.soa().first().map(|soa| SoaDetails {
            refresh: soa.refresh(),
            retry: soa.retry(),
            expire: soa.expire(),
            minimum: soa.minimum(),
        })
    });

    // Group servers by their SOA serial
    let mut serial_groups: HashMap<Option<u32>, Vec<ServerData>> = HashMap::new();
    for sd in server_data.into_values() {
        serial_groups.entry(sd.serial).or_default().push(sd);
    }

    // Build SerialGroup list, sorted: current first, then by group size descending, errors/None last
    let mut resolver_groups: Vec<SerialGroup> = serial_groups
        .into_iter()
        .map(|(serial, servers)| {
            let is_current = match (serial, authoritative_serial) {
                (Some(s), Some(auth_s)) => s == auth_s,
                _ => false,
            };
            // Collect unique records across all servers in this group
            let mut records: Vec<Record> = Vec::new();
            for sd in &servers {
                for record in &sd.records {
                    if !records.contains(record) {
                        records.push(record.clone());
                    }
                }
            }
            let server_infos: Vec<ResolverInfo> = servers.into_iter().map(|sd| sd.info).collect();
            SerialGroup {
                serial,
                is_current,
                servers: server_infos,
                records,
            }
        })
        .collect();

    resolver_groups.sort_by(|a, b| {
        b.is_current
            .cmp(&a.is_current)
            .then_with(|| {
                // None serial (errors) last
                let a_has = a.serial.is_some();
                let b_has = b.serial.is_some();
                b_has.cmp(&a_has)
            })
            .then_with(|| b.servers.len().cmp(&a.servers.len()))
    });

    let unreachable_servers: Vec<ResolverInfo> = unreachable.into_iter().map(|sd| sd.info).collect();

    PropagationResults {
        domain_name: domain_name.to_string(),
        record_types: user_record_types.to_vec(),
        authoritative_serial,
        authoritative_ns: auth_info.authoritative_ns,
        soa_details,
        resolver_groups,
        unreachable_servers,
        total_resolvers,
    }
}

/// Intermediate per-server data collected from lookups
struct ServerData {
    info: ResolverInfo,
    serial: Option<u32>,
    records: Vec<Record>,
    has_error: bool,
}

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct PropagationResults {
    pub domain_name: String,
    pub record_types: Vec<RecordType>,
    pub authoritative_serial: Option<u32>,
    pub authoritative_ns: Vec<AuthoritativeNsInfo>,
    pub soa_details: Option<SoaDetails>,
    pub resolver_groups: Vec<SerialGroup>,
    pub unreachable_servers: Vec<ResolverInfo>,
    pub total_resolvers: usize,
}

impl PropagationResults {
    pub fn propagation_pct(&self) -> usize {
        if self.total_resolvers == 0 {
            return 0;
        }
        let current_count: usize = self
            .resolver_groups
            .iter()
            .filter(|g| g.is_current)
            .map(|g| g.servers.len())
            .sum();
        current_count * 100 / self.total_resolvers
    }

    pub fn is_fully_propagated(&self) -> bool {
        self.propagation_pct() == 100
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthoritativeNsInfo {
    pub ns_name: String,
    pub ip: String,
    pub serial: Option<u32>,
    pub records: Vec<Record>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SoaDetails {
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct SerialGroup {
    pub serial: Option<u32>,
    pub is_current: bool,
    pub servers: Vec<ResolverInfo>,
    pub records: Vec<Record>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolverInfo {
    pub name: String,
    pub ip: String,
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

pub struct PropagationOutput<'a> {
    env: Environment<'a, PropagationConfig>,
    results: PropagationResults,
}

impl PropagationOutput<'_> {
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
            #[serde(flatten)]
            results: PropagationResults,
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
            results: self.results,
        };

        output::output(&self.env.app_config.output_config, &data)?;
        Ok(ExitStatus::Ok)
    }

    fn summary_output(self) -> PartialResult<ExitStatus> {
        output::output(&self.env.app_config.output_config, &self.results)?;

        if self.env.console.not_quiet() {
            self.env.console.finished();
        }

        Ok(ExitStatus::Ok)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::lookup::{Lookup, LookupResult, Response};
    use crate::resources::rdata::SOA;
    use crate::resources::RData;
    use hickory_resolver::Name;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::Duration;

    fn make_nameserver(ip: Ipv4Addr, name: &str) -> Arc<NameServerConfig> {
        Arc::new(NameServerConfig::udp_with_name((ip, 53), name.to_string()))
    }

    fn make_a_record(domain: &str, ip: Ipv4Addr) -> Record {
        Record::new_for_test(Name::from_utf8(domain).unwrap(), RecordType::A, 300, RData::A(ip))
    }

    fn make_soa_record(domain: &str, serial: u32) -> Record {
        Record::new_for_test(
            Name::from_utf8(domain).unwrap(),
            RecordType::SOA,
            3600,
            RData::SOA(SOA::new(
                Name::from_utf8("ns1.example.com").unwrap(),
                Name::from_utf8("admin.example.com").unwrap(),
                serial,
                7200,
                1800,
                1209600,
                3600,
            )),
        )
    }

    fn make_lookup(ns: Arc<NameServerConfig>, records: Vec<Record>, query_type: RecordType) -> Lookup {
        let query = crate::resolver::UniQuery {
            name: Name::from_utf8("example.com").unwrap(),
            record_type: query_type,
        };
        Lookup::new_for_test(
            query,
            ns,
            LookupResult::Response(Response::new_for_test(records, Duration::from_millis(10))),
        )
    }

    fn make_error_lookup(ns: Arc<NameServerConfig>, query_type: RecordType) -> Lookup {
        let query = crate::resolver::UniQuery {
            name: Name::from_utf8("example.com").unwrap(),
            record_type: query_type,
        };
        Lookup::new_for_test(query, ns, LookupResult::Error(crate::resolver::Error::Timeout))
    }

    // -----------------------------------------------------------------------
    // compute_propagation tests
    // -----------------------------------------------------------------------

    #[test]
    fn all_resolvers_same_serial_fully_propagated() {
        let ns1 = make_nameserver(Ipv4Addr::new(1, 1, 1, 1), "Cloudflare 1");
        let ns2 = make_nameserver(Ipv4Addr::new(8, 8, 8, 8), "Google 1");

        let soa = make_soa_record("example.com", 2026021401);
        let a_record = make_a_record("example.com", Ipv4Addr::new(93, 184, 216, 34));

        let lookups = Lookups::new(vec![
            make_lookup(ns1.clone(), vec![soa.clone()], RecordType::SOA),
            make_lookup(ns1, vec![a_record.clone()], RecordType::A),
            make_lookup(ns2.clone(), vec![soa], RecordType::SOA),
            make_lookup(ns2, vec![a_record], RecordType::A),
        ]);

        let auth_info = AuthoritativeInfo {
            authoritative_serial: Some(2026021401),
            authoritative_ns: vec![AuthoritativeNsInfo {
                ns_name: "ns1.example.com.".to_string(),
                ip: "10.0.0.1".to_string(),
                serial: Some(2026021401),
                records: vec![],
                error: None,
            }],
            soa_details: Some(SoaDetails {
                refresh: 7200,
                retry: 1800,
                expire: 1209600,
                minimum: 3600,
            }),
        };

        let results = compute_propagation("example.com", &[RecordType::A], &lookups, auth_info);

        assert_eq!(results.total_resolvers, 2);
        assert_eq!(results.propagation_pct(), 100);
        assert!(results.is_fully_propagated());
        assert_eq!(results.resolver_groups.len(), 1);
        assert!(results.resolver_groups[0].is_current);
        assert_eq!(results.resolver_groups[0].serial, Some(2026021401));
    }

    #[test]
    fn split_serials_partial_propagation() {
        let ns1 = make_nameserver(Ipv4Addr::new(1, 1, 1, 1), "Cloudflare 1");
        let ns2 = make_nameserver(Ipv4Addr::new(8, 8, 8, 8), "Google 1");
        let ns3 = make_nameserver(Ipv4Addr::new(9, 9, 9, 10), "Quad9 1");

        let soa_new = make_soa_record("example.com", 2026021402);
        let soa_old = make_soa_record("example.com", 2026021401);
        let a_new = make_a_record("example.com", Ipv4Addr::new(93, 184, 216, 34));
        let a_old = make_a_record("example.com", Ipv4Addr::new(93, 184, 216, 33));

        let lookups = Lookups::new(vec![
            make_lookup(ns1.clone(), vec![soa_new.clone()], RecordType::SOA),
            make_lookup(ns1, vec![a_new.clone()], RecordType::A),
            make_lookup(ns2.clone(), vec![soa_new], RecordType::SOA),
            make_lookup(ns2, vec![a_new], RecordType::A),
            make_lookup(ns3.clone(), vec![soa_old], RecordType::SOA),
            make_lookup(ns3, vec![a_old], RecordType::A),
        ]);

        let auth_info = AuthoritativeInfo {
            authoritative_serial: Some(2026021402),
            authoritative_ns: vec![],
            soa_details: None,
        };

        let results = compute_propagation("example.com", &[RecordType::A], &lookups, auth_info);

        assert_eq!(results.total_resolvers, 3);
        assert_eq!(results.propagation_pct(), 66);
        assert!(!results.is_fully_propagated());
        assert_eq!(results.resolver_groups.len(), 2);
        // First group should be current
        assert!(results.resolver_groups[0].is_current);
        assert_eq!(results.resolver_groups[0].servers.len(), 2);
        // Second group should be stale
        assert!(!results.resolver_groups[1].is_current);
        assert_eq!(results.resolver_groups[1].servers.len(), 1);
    }

    #[test]
    fn authoritative_ns_serial_mismatch() {
        let auth_info = AuthoritativeInfo {
            authoritative_serial: Some(2026021402),
            authoritative_ns: vec![
                AuthoritativeNsInfo {
                    ns_name: "ns1.example.com.".to_string(),
                    ip: "10.0.0.1".to_string(),
                    serial: Some(2026021402),
                    records: vec![],
                    error: None,
                },
                AuthoritativeNsInfo {
                    ns_name: "ns2.example.com.".to_string(),
                    ip: "10.0.0.2".to_string(),
                    serial: Some(2026021401),
                    records: vec![],
                    error: None,
                },
            ],
            soa_details: None,
        };

        // The authoritative_serial should be the max
        assert_eq!(auth_info.authoritative_serial, Some(2026021402));
        // ns2 has a different serial — zone sync issue
        let serials: Vec<u32> = auth_info.authoritative_ns.iter().filter_map(|ns| ns.serial).collect();
        assert!(serials.iter().any(|s| *s != 2026021402));
    }

    #[test]
    fn resolver_errors_handled_gracefully() {
        let ns1 = make_nameserver(Ipv4Addr::new(1, 1, 1, 1), "Cloudflare 1");
        let ns2 = make_nameserver(Ipv4Addr::new(8, 8, 8, 8), "Google 1");

        let soa = make_soa_record("example.com", 2026021401);
        let a_record = make_a_record("example.com", Ipv4Addr::new(93, 184, 216, 34));

        let lookups = Lookups::new(vec![
            make_lookup(ns1.clone(), vec![soa], RecordType::SOA),
            make_lookup(ns1, vec![a_record], RecordType::A),
            make_error_lookup(ns2.clone(), RecordType::SOA),
            make_error_lookup(ns2, RecordType::A),
        ]);

        let auth_info = AuthoritativeInfo {
            authoritative_serial: Some(2026021401),
            authoritative_ns: vec![],
            soa_details: None,
        };

        let results = compute_propagation("example.com", &[RecordType::A], &lookups, auth_info);

        // Unreachable servers are excluded from the count
        assert_eq!(results.total_resolvers, 1);
        assert_eq!(results.propagation_pct(), 100);
        // ns2 should be in unreachable_servers, not in resolver_groups
        assert_eq!(results.unreachable_servers.len(), 1);
        assert_eq!(results.unreachable_servers[0].name, "Google 1");
        assert!(results.resolver_groups.iter().all(|g| g.serial.is_some()));
    }

    #[test]
    fn no_authoritative_serial_falls_back_to_highest_recursive() {
        let ns1 = make_nameserver(Ipv4Addr::new(1, 1, 1, 1), "Cloudflare 1");
        let ns2 = make_nameserver(Ipv4Addr::new(8, 8, 8, 8), "Google 1");

        let soa_new = make_soa_record("example.com", 2026021402);
        let soa_old = make_soa_record("example.com", 2026021401);

        let lookups = Lookups::new(vec![
            make_lookup(ns1.clone(), vec![soa_new], RecordType::SOA),
            make_lookup(ns2.clone(), vec![soa_old], RecordType::SOA),
        ]);

        // No authoritative info available
        let auth_info = AuthoritativeInfo::empty();

        let results = compute_propagation("example.com", &[RecordType::A], &lookups, auth_info);

        // Should fall back to highest serial from recursive
        assert_eq!(results.authoritative_serial, Some(2026021402));
        assert_eq!(results.propagation_pct(), 50);
    }

    #[test]
    fn soa_details_extraction() {
        let auth_info = AuthoritativeInfo {
            authoritative_serial: Some(2026021401),
            authoritative_ns: vec![],
            soa_details: Some(SoaDetails {
                refresh: 7200,
                retry: 1800,
                expire: 1209600,
                minimum: 3600,
            }),
        };

        assert_eq!(auth_info.soa_details.as_ref().unwrap().refresh, 7200);
        assert_eq!(auth_info.soa_details.as_ref().unwrap().retry, 1800);
        assert_eq!(auth_info.soa_details.as_ref().unwrap().minimum, 3600);
    }

    // -----------------------------------------------------------------------
    // Summary output tests
    // -----------------------------------------------------------------------

    #[test]
    fn summary_output_fully_propagated() {
        let results = PropagationResults {
            domain_name: "example.com".to_string(),
            record_types: vec![RecordType::A],
            authoritative_serial: Some(2026021401),
            authoritative_ns: vec![AuthoritativeNsInfo {
                ns_name: "ns1.example.com.".to_string(),
                ip: "10.0.0.1".to_string(),
                serial: Some(2026021401),
                records: vec![make_a_record("example.com", Ipv4Addr::new(93, 184, 216, 34))],
                error: None,
            }],
            soa_details: Some(SoaDetails {
                refresh: 7200,
                retry: 1800,
                expire: 1209600,
                minimum: 3600,
            }),
            resolver_groups: vec![SerialGroup {
                serial: Some(2026021401),
                is_current: true,
                servers: vec![
                    ResolverInfo {
                        name: "Cloudflare 1".to_string(),
                        ip: "1.1.1.1".to_string(),
                    },
                    ResolverInfo {
                        name: "Google 1".to_string(),
                        ip: "8.8.8.8".to_string(),
                    },
                ],
                records: vec![make_a_record("example.com", Ipv4Addr::new(93, 184, 216, 34))],
            }],
            unreachable_servers: vec![],
            total_resolvers: 2,
        };

        let opts = SummaryOptions::default();
        let mut buf = Vec::new();
        results.output(&mut buf, &opts).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("DNS Propagation for example.com"));
        assert!(output.contains("Authoritative Nameservers"));
        assert!(output.contains("SOA serial: 2026021401"));
        assert!(output.contains("Recursive Resolvers"));
        assert!(output.contains("Current serial 2026021401"));
        assert!(output.contains("100% complete"));
    }

    #[test]
    fn summary_output_partial_propagation() {
        let results = PropagationResults {
            domain_name: "example.com".to_string(),
            record_types: vec![RecordType::A],
            authoritative_serial: Some(2026021402),
            authoritative_ns: vec![],
            soa_details: None,
            resolver_groups: vec![
                SerialGroup {
                    serial: Some(2026021402),
                    is_current: true,
                    servers: vec![ResolverInfo {
                        name: "Cloudflare 1".to_string(),
                        ip: "1.1.1.1".to_string(),
                    }],
                    records: vec![make_a_record("example.com", Ipv4Addr::new(93, 184, 216, 34))],
                },
                SerialGroup {
                    serial: Some(2026021401),
                    is_current: false,
                    servers: vec![ResolverInfo {
                        name: "Mullvad 1".to_string(),
                        ip: "194.242.2.2".to_string(),
                    }],
                    records: vec![make_a_record("example.com", Ipv4Addr::new(93, 184, 216, 33))],
                },
            ],
            unreachable_servers: vec![],
            total_resolvers: 2,
        };

        let opts = SummaryOptions::default();
        let mut buf = Vec::new();
        results.output(&mut buf, &opts).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("Current serial 2026021402"));
        assert!(output.contains("Stale serial 2026021401"));
        assert!(output.contains("50% complete"));
    }

    #[test]
    fn json_serialization() {
        let results = PropagationResults {
            domain_name: "example.com".to_string(),
            record_types: vec![RecordType::A],
            authoritative_serial: Some(2026021401),
            authoritative_ns: vec![AuthoritativeNsInfo {
                ns_name: "ns1.example.com.".to_string(),
                ip: "10.0.0.1".to_string(),
                serial: Some(2026021401),
                records: vec![],
                error: None,
            }],
            soa_details: Some(SoaDetails {
                refresh: 7200,
                retry: 1800,
                expire: 1209600,
                minimum: 3600,
            }),
            resolver_groups: vec![SerialGroup {
                serial: Some(2026021401),
                is_current: true,
                servers: vec![ResolverInfo {
                    name: "Cloudflare 1".to_string(),
                    ip: "1.1.1.1".to_string(),
                }],
                records: vec![],
            }],
            unreachable_servers: vec![],
            total_resolvers: 1,
        };

        let json = serde_json::to_string(&results);
        assert!(json.is_ok());
        let json = json.unwrap();
        assert!(json.contains("\"domain_name\":\"example.com\""));
        assert!(json.contains("\"authoritative_serial\":2026021401"));
        assert!(json.contains("\"resolver_groups\""));
        assert!(json.contains("\"is_current\":true"));
        assert!(json.contains("\"soa_details\""));
    }

    #[test]
    fn empty_lookups_handled() {
        let lookups = Lookups::new(vec![]);
        let auth_info = AuthoritativeInfo::empty();
        let results = compute_propagation("example.com", &[RecordType::A], &lookups, auth_info);

        assert_eq!(results.total_resolvers, 0);
        assert_eq!(results.propagation_pct(), 0);
        assert!(results.resolver_groups.is_empty());
        assert!(results.authoritative_serial.is_none());
    }
}
