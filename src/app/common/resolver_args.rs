//! Shared resolver configuration parsed from CLI args.
//!
//! Used by both mhost and mdive to avoid duplicating resolver setup logic.

use std::collections::HashSet;
use std::str::FromStr;
use std::time::Duration;

use clap::builder::ValueParser;
use clap::ArgMatches;

use crate::nameserver::{predefined, NameServerConfig, NameServerConfigGroup, Protocol};
use crate::resolver::ResolverGroupBuilder;
use crate::resolver::ResolverGroup;

/// Shared resolver configuration, parsed from CLI args.
///
/// Both mhost and mdive use the same arg names so `from_matches()` works for both.
#[derive(Clone, Debug)]
pub struct ResolverArgs {
    pub timeout: Duration,
    pub nameservers: Vec<String>,
    pub predefined: bool,
    pub predefined_filter: Vec<String>,
    pub no_system_lookups: bool,
    pub ipv4_only: bool,
    pub ipv6_only: bool,
}

impl ResolverArgs {
    /// Parse from clap `ArgMatches`. Both mhost and mdive use the same arg names.
    pub fn from_matches(matches: &ArgMatches) -> Self {
        let timeout = {
            let secs = *matches.get_one::<u64>("timeout").unwrap(); // Safe: clap validates
            Duration::from_secs(secs)
        };
        let nameservers = matches
            .get_many::<String>("nameservers")
            .map(|xs| xs.map(ToString::to_string).collect())
            .unwrap_or_default();
        let predefined = matches.get_flag("predefined");
        let predefined_filter = matches
            .get_many::<String>("predefined-filter")
            .map(|xs| xs.map(ToString::to_string).collect())
            .unwrap_or_else(|| vec!["udp".to_string()]);
        let no_system_lookups = matches.get_flag("no-system-lookups");
        let ipv4_only = matches.get_flag("ipv4-only");
        let ipv6_only = matches.get_flag("ipv6-only");

        ResolverArgs {
            timeout,
            nameservers,
            predefined,
            predefined_filter,
            no_system_lookups,
            ipv4_only,
            ipv6_only,
        }
    }

    /// Build a `ResolverGroup` from these args.
    ///
    /// Handles: system servers, custom `-s` servers, `-p` predefined filtering,
    /// IP family filtering, and timeout.
    pub async fn build_resolver_group(&self) -> Result<ResolverGroup, String> {
        let mut configs: Vec<NameServerConfig> = Vec::new();

        if !self.no_system_lookups {
            let system = NameServerConfigGroup::from_system_config()
                .map_err(|e| format!("failed to load system nameservers: {e}"))?;
            configs.extend(system);
        }

        for ns_str in &self.nameservers {
            let ns = NameServerConfig::from_str(ns_str)
                .map_err(|e| format!("failed to parse nameserver '{ns_str}': {e}"))?;
            configs.push(ns);
        }

        if self.predefined {
            configs.extend(filter_predefined_nameservers(&self.predefined_filter));
        }

        // Filter by IP family
        if self.ipv4_only {
            configs.retain(|ns| ns.ip_addr().is_ipv4());
        } else if self.ipv6_only {
            configs.retain(|ns| ns.ip_addr().is_ipv6());
        }

        let group = ResolverGroupBuilder::new()
            .nameservers(configs)
            .timeout(self.timeout)
            .build()
            .await
            .map_err(|e| format!("{e:#}"))?;

        if group.is_empty() {
            return Err("no nameservers available; add -s, -p, or remove -S".to_string());
        }

        Ok(group)
    }
}

/// Filter predefined nameserver configs by protocol strings.
///
/// Shared between `ResolverArgs::build_resolver_group()` and mhost's `resolver.rs`.
pub fn filter_predefined_nameservers(protocol_filters: &[String]) -> Vec<NameServerConfig> {
    let filter: HashSet<Protocol> = protocol_filters
        .iter()
        .flat_map(|x| Protocol::from_str(x.as_str()))
        .collect();
    predefined::nameserver_configs()
        .into_iter()
        .filter(|x| filter.contains(&x.protocol()))
        .collect()
}

/// Clap value parser for `u64` range validation.
pub fn u64_range(min: u64, max: u64) -> ValueParser {
    ValueParser::from(move |s: &str| -> Result<u64, String> {
        let n: u64 = s.parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
        if n < min || n > max {
            return Err(format!("value must be between {} and {}", min, max));
        }
        Ok(n)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_predefined_udp_only() {
        let configs = filter_predefined_nameservers(&["udp".to_string()]);
        assert!(!configs.is_empty());
        assert!(configs.iter().all(|c| c.protocol() == Protocol::Udp));
    }

    #[test]
    fn filter_predefined_tls_only() {
        let configs = filter_predefined_nameservers(&["tls".to_string()]);
        assert!(!configs.is_empty());
        assert!(configs.iter().all(|c| c.protocol() == Protocol::Tls));
    }

    #[test]
    fn filter_predefined_multiple_protocols() {
        let configs = filter_predefined_nameservers(&["udp".to_string(), "tcp".to_string()]);
        assert!(!configs.is_empty());
        assert!(configs
            .iter()
            .all(|c| c.protocol() == Protocol::Udp || c.protocol() == Protocol::Tcp));
    }

    #[test]
    fn filter_predefined_invalid_protocol_ignored() {
        let configs = filter_predefined_nameservers(&["invalid".to_string()]);
        assert!(configs.is_empty());
    }
}
