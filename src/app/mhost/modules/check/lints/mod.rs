// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use anyhow::anyhow;
use serde::Serialize;
use tracing::info;

use soa::Soa;

use crate::app::modules::check::config::CheckConfig;
use crate::app::modules::{AppModule, Environment, PartialError, PartialResult, RunInfo};
use crate::app::output::summary::{SummaryFormatter, SummaryOptions};
use crate::app::output::OutputType;
use crate::app::resolver::AppResolver;
use crate::app::utils::time;
use crate::app::{output, AppConfig, ExitStatus};
use crate::resolver::{Lookups, MultiQuery};
use crate::{Name, RecordType};
use std::io::Write;

#[doc(hidden)]
macro_rules! intermediate_lookups {
    ($Self:ident, $query:ident, resolver: $resolver:ident, $msg:expr, $($args:ident),*) => {{
        __intermediate_lookups!(Slf: $Self, query: $query, resolver: $resolver, msg: $msg, $($args),*)
    }};
    ($Self:ident, $query:ident, resolver: $resolver:ident, $msg:expr) => {{
        __intermediate_lookups!(Slf: $Self, query: $query, resolver: $resolver, msg: $msg,)
    }};
    ($Self:ident, $query:ident, $msg:expr, $($args:ident),*) => {{
        let resolver = &$Self.app_resolver;
        __intermediate_lookups!(Slf: $Self, query: $query, resolver: resolver, msg: $msg, $($args),*)
    }};
    ($Self:ident, $query:ident, $msg:expr) => {{
        let resolver = &$Self.app_resolver;
        __intermediate_lookups!(Slf: $Self, query: $query, resolver: resolver, msg: $msg,)
    }};
}

macro_rules! __intermediate_lookups {
    (Slf: $Self:ident, query: $query:ident, resolver: $resolver:ident, msg: $msg:expr, $($args:ident),*) => {
        {
            let query: MultiQuery = $query;
            if $Self.env.console.show_partial_headers() && $Self.env.mod_config.show_intermediate_lookups {
                $Self.env.console.print_lookup_estimates(&$resolver.resolvers(), &query);
            }

            info!($msg, $($args),*);
            let (lookups, run_time) = time($resolver.lookup(query)).await?;
            info!("Finished Lookups.");

            if $Self.env.mod_config.show_intermediate_lookups {
                $Self
                    .env
                    .console
                    .print_partial_results(&$Self.env.app_config.output_config, &lookups, run_time)?;
            }
            lookups
        }
    };
}

#[doc(hidden)]
macro_rules! print_check_results {
    ($self:ident, $results:expr, $not_found_msg:expr) => {
        if $self.env.console.show_partial_results() {
            for r in &$results {
                match r {
                    CheckResult::NotFound() => $self.env.console.info($not_found_msg),
                    // Results quote DNS data, which must not act on the terminal.
                    CheckResult::Ok(str) => $self.env.console.ok($crate::app::common::records::term_safe(str)),
                    CheckResult::Warning(str) => $self
                        .env
                        .console
                        .attention($crate::app::common::records::term_safe(str)),
                    CheckResult::Failed(str) => $self.env.console.failed($crate::app::common::records::term_safe(str)),
                }
            }
        }
    };
}

pub mod axfr;
pub mod caa;
pub mod cnames;
pub mod delegation;
pub mod dmarc;
pub mod dnssec_lint;
pub mod https_svcb;
pub mod mx;
pub mod ns;
pub mod open_resolver;
pub mod soa;
pub mod spf;
pub mod ttl;

// Re-export shared lint types and functions from app::common::lints
pub use crate::app::common::lints::CheckResult;
pub use crate::app::common::lints::{
    check_caa, check_cname_apex, check_dmarc_records, check_dnssec, check_https_svcb_mode, check_mx_sync,
    check_ns_count, check_spf, check_ttl, is_dmarc,
};

#[derive(Debug, Serialize)]
pub struct CheckResults {
    lookups: Lookups,
    soa: Option<Vec<CheckResult>>,
    ns: Option<Vec<CheckResult>>,
    cnames: Option<Vec<CheckResult>>,
    mx: Option<Vec<CheckResult>>,
    spf: Option<Vec<CheckResult>>,
    dmarc: Option<Vec<CheckResult>>,
    caa: Option<Vec<CheckResult>>,
    ttl: Option<Vec<CheckResult>>,
    dnssec: Option<Vec<CheckResult>>,
    https_svcb: Option<Vec<CheckResult>>,
    axfr: Option<Vec<CheckResult>>,
    open_resolver: Option<Vec<CheckResult>>,
    delegation: Option<Vec<CheckResult>>,
}

macro_rules! check_result_builders {
    ($($field:ident),+ $(,)?) => {
        $(
            pub fn $field(self, $field: Option<Vec<CheckResult>>) -> CheckResults {
                CheckResults { $field, ..self }
            }
        )+
    };
}

impl CheckResults {
    pub fn new(lookups: Lookups) -> CheckResults {
        CheckResults {
            lookups,
            soa: None,
            ns: None,
            cnames: None,
            mx: None,
            spf: None,
            dmarc: None,
            caa: None,
            ttl: None,
            dnssec: None,
            https_svcb: None,
            axfr: None,
            open_resolver: None,
            delegation: None,
        }
    }

    check_result_builders!(
        soa,
        ns,
        cnames,
        mx,
        spf,
        dmarc,
        caa,
        ttl,
        dnssec,
        https_svcb,
        axfr,
        open_resolver,
        delegation
    );

    fn has_any<F: Fn(&CheckResult) -> bool>(&self, predicate: F) -> bool {
        let all_checks: [&Option<Vec<CheckResult>>; 13] = [
            &self.soa,
            &self.ns,
            &self.cnames,
            &self.mx,
            &self.spf,
            &self.dmarc,
            &self.caa,
            &self.ttl,
            &self.dnssec,
            &self.https_svcb,
            &self.axfr,
            &self.open_resolver,
            &self.delegation,
        ];
        all_checks
            .iter()
            .any(|check| check.as_ref().is_some_and(|results| results.iter().any(&predicate)))
    }

    pub fn has_warnings(&self) -> bool {
        self.has_any(|x| x.is_warning())
    }

    pub fn has_failures(&self) -> bool {
        self.has_any(|x| x.is_failed())
    }
}

pub struct Check {}

impl AppModule<CheckConfig> for Check {}

impl Check {
    pub async fn init<'a>(app_config: &'a AppConfig, config: &'a CheckConfig) -> PartialResult<LookupAllThereIs<'a>> {
        if app_config.output == OutputType::Json && config.partial_results {
            return Err(anyhow!("JSON output is incompatible with partial result output").into());
        }

        let env = Self::init_env(app_config, config)?;
        let domain_name = env.name_builder.from_str(&config.domain_name)?;
        let app_resolver = AppResolver::create_resolvers(app_config).await?;

        env.console
            .print_resolver_opts(app_resolver.resolver_group_opts(), app_resolver.resolver_opts());

        Ok(LookupAllThereIs {
            env,
            domain_name,
            app_resolver,
        })
    }
}

/// Splits nameserver addresses into public ones and the rest. The zone under check names its
/// nameservers, so a hostile zone could point probes (AXFR, open resolver, delegation, DNSKEY)
/// at the user's own network; only public addresses are probed.
fn public_ips(ips: Vec<std::net::IpAddr>) -> (Vec<std::net::IpAddr>, Vec<std::net::IpAddr>) {
    ips.into_iter().partition(|ip| crate::nameserver::is_global_ip(*ip))
}

/// The addresses to probe among `ips`: the public ones. When addresses resolved but none is
/// public, the error says so — callers report it instead of claiming nothing resolved.
fn select_targets(ips: Vec<std::net::IpAddr>) -> std::result::Result<Vec<std::net::IpAddr>, String> {
    let (public, skipped) = public_ips(ips);
    if public.is_empty() && !skipped.is_empty() {
        let skipped: Vec<String> = skipped.iter().map(|ip| ip.to_string()).collect();
        return Err(format!(
            "Nameserver addresses {} are not public and were not probed",
            skipped.join(", ")
        ));
    }
    Ok(public)
}

/// The public addresses among the unique A then AAAA addresses in `lookups`, cf. [`select_targets`];
/// lists the left-out ones in the partial output.
fn probe_targets(
    lookups: &Lookups,
    console: &crate::app::console::Console,
) -> std::result::Result<Vec<std::net::IpAddr>, String> {
    let ips = unique_ips(lookups);
    let skipped: Vec<String> = ips
        .iter()
        .filter(|ip| !crate::nameserver::is_global_ip(**ip))
        .map(|ip| ip.to_string())
        .collect();
    if !skipped.is_empty() && console.show_partial_results() {
        console.info(format!(
            "Not probing non-public nameserver addresses: {}",
            skipped.join(", ")
        ));
    }
    select_targets(ips)
}

/// The unique A then AAAA addresses in `lookups`, each family in address order so that probes go
/// to the same servers on every run.
fn unique_ips(lookups: &Lookups) -> Vec<std::net::IpAddr> {
    use crate::resolver::lookup::Uniquify;
    let mut ipv4s: Vec<_> = lookups.a().unique().to_owned().into_iter().collect();
    ipv4s.sort();
    let mut ipv6s: Vec<_> = lookups.aaaa().unique().to_owned().into_iter().collect();
    ipv6s.sort();
    ipv4s
        .into_iter()
        .map(std::net::IpAddr::from)
        .chain(ipv6s.into_iter().map(std::net::IpAddr::from))
        .collect()
}

pub struct LookupAllThereIs<'a> {
    env: Environment<'a, CheckConfig>,
    domain_name: Name,
    app_resolver: AppResolver,
}

impl<'a> LookupAllThereIs<'a> {
    pub async fn lookup_all_records(self) -> PartialResult<Soa<'a>> {
        let record_types = {
            use RecordType::*;
            vec![
                // TODO: AXFR seems to kill dnsmasq in the macOS test-env
                //A, AAAA, ANAME, ANY, AXFR, CAA, CNAME, IXFR, MX, NS, OPT, SOA, SRV, TXT, DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM,
                A, AAAA, ANAME, ANY, CAA, CNAME, DNSKEY, DS, HINFO, HTTPS, IXFR, MX, NAPTR, NS, NSEC, NSEC3, NSEC3PARAM,
                OPENPGPKEY, OPT, RRSIG, SOA, SRV, SSHFP, SVCB, TLSA, TXT,
            ]
        };
        let query = MultiQuery::multi_record(self.domain_name.clone(), record_types)?;

        self.env.console.print_partial_headers(
            "Running DNS lookups for all available records.",
            self.app_resolver.resolvers(),
            &query,
        );

        info!("Running lookups of all records of domain.");
        let (lookups, run_time) = time(self.app_resolver.lookup(query)).await?;
        info!("Finished Lookups.");

        self.env
            .console
            .print_partial_results(&self.env.app_config.output_config, &lookups, run_time)?;

        if !lookups.has_records() {
            self.env.console.failed("No records found. Aborting.");
            return Err(PartialError::Failed(ExitStatus::Abort));
        }

        let check_results = CheckResults::new(lookups);

        Ok(Soa {
            env: self.env,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            check_results,
        })
    }
}

pub struct OutputCheckResults<'a> {
    env: Environment<'a, CheckConfig>,
    #[allow(dead_code)]
    domain_name: Name,
    check_results: CheckResults,
}

impl OutputCheckResults<'_> {
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
            check_results: CheckResults,
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
            check_results: self.check_results,
        };

        output::output(&self.env.app_config.output_config, &data)?;
        Ok(ExitStatus::Ok)
    }

    #[allow(clippy::unnecessary_wraps)]
    fn summary_output(self) -> PartialResult<ExitStatus> {
        let exit = if self.check_results.has_failures() {
            self.env.console.failed("Found failures");
            ExitStatus::CheckFailed
        } else if self.check_results.has_warnings() {
            self.env.console.attention("Found warnings");
            ExitStatus::CheckFailed
        } else {
            self.env.console.ok("No issues found.");
            ExitStatus::Ok
        };

        self.env.console.print_finished();
        Ok(exit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn unique_ips_are_ordered() {
        use crate::nameserver::NameServerConfig;
        use crate::resolver::lookup::{Lookup, LookupResult, Response};
        use crate::resolver::UniQuery;
        use crate::resources::{RData, Record};
        use std::net::Ipv4Addr;
        use std::sync::Arc;
        use std::time::Duration;

        let records = [9u8, 3, 7, 1]
            .iter()
            .map(|i| {
                Record::new_for_test(
                    Name::from_ascii("ns.example.com.").unwrap(),
                    RecordType::A,
                    300,
                    RData::A(Ipv4Addr::new(192, 0, 2, *i)),
                )
            })
            .collect();
        let lookup = Lookup::new_for_test(
            UniQuery::new("ns.example.com.", RecordType::A).unwrap(),
            Arc::new(NameServerConfig::udp((Ipv4Addr::new(192, 0, 2, 53), 53))),
            LookupResult::Response(Response::new_for_test(records, Duration::from_millis(1))),
        );
        let ips = unique_ips(&Lookups::new(vec![lookup]));
        let expected: Vec<IpAddr> = ["192.0.2.1", "192.0.2.3", "192.0.2.7", "192.0.2.9"]
            .iter()
            .map(|ip| ip.parse().unwrap())
            .collect();
        assert_eq!(ips, expected);
    }

    #[test]
    fn only_non_public_addresses_is_a_reason_not_an_empty_list() {
        let ips = |list: &[&str]| -> Vec<IpAddr> { list.iter().map(|ip| ip.parse().unwrap()).collect() };

        let reason = select_targets(ips(&["10.0.0.53", "127.0.0.1"])).unwrap_err();
        assert!(
            reason.contains("10.0.0.53") && reason.contains("not public"),
            "{reason}"
        );
        assert_eq!(
            select_targets(ips(&["10.0.0.53", "8.8.8.8"])).unwrap(),
            ips(&["8.8.8.8"])
        );
        assert!(select_targets(Vec::new()).unwrap().is_empty());
    }

    #[test]
    fn public_ips_leaves_out_non_public_addresses() {
        let ips: Vec<IpAddr> = [
            "192.0.2.1",
            "127.0.0.1",
            "8.8.8.8",
            "10.0.0.53",
            "169.254.169.254",
            "::1",
        ]
        .iter()
        .map(|ip| ip.parse().unwrap())
        .collect();
        let (public, skipped) = public_ips(ips);
        assert_eq!(public, vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
        assert_eq!(skipped.len(), 5);
    }
}
