use std::collections::HashSet;
use std::io::Write;
use std::net::IpAddr;
use std::str::FromStr;

use anyhow::{Context, Result};
use ipnetwork::IpNetwork;
use serde::Serialize;
use tokio::time::Duration;
use tracing::{debug, info};

use crate::app::modules::lookup::config::LookupConfig;
use crate::app::modules::lookup::service_spec::ServiceSpec;
use crate::app::modules::{AppModule, Environment, PartialResult};
use crate::app::output::summary::{SummaryFormatter, SummaryOptions};
use crate::app::output::OutputType;
use crate::app::resolver::{AppResolver, NameBuilder};
use crate::app::utils::time;
use crate::app::{output, AppConfig, ExitStatus};
use crate::resolver::lookup::Uniquify;
use crate::resolver::{Lookups, MultiQuery};
use crate::resources::NameToIpAddr;
use crate::services::whois::{self, QueryType, WhoisClient, WhoisClientOpts, WhoisResponses};
use crate::{Name, RecordType};

pub struct Lookup {}

impl AppModule<LookupConfig> for Lookup {}

impl Lookup {
    pub async fn init<'a>(app_config: &'a AppConfig, config: &'a LookupConfig) -> PartialResult<DnsLookups<'a>> {
        let env = Self::init_env(app_config, config)?;

        let domain_name = if config.parse_as_service {
            ServiceSpec::from_str(&config.domain_name)?.to_domain_name()
        } else {
            config.domain_name.clone()
        };
        let query = Lookup::build_query(&env.name_builder, &domain_name, &config.record_types)?;
        debug!("Querying: {:?}", query);
        let app_resolver = AppResolver::create_resolvers(app_config).await?;

        env.console
            .print_resolver_opts(app_resolver.resolver_group_opts(), &app_resolver.resolver_opts());

        Ok(DnsLookups {
            env,
            query,
            app_resolver,
        })
    }

    fn build_query(name_builder: &NameBuilder, domain_name: &str, record_types: &[RecordType]) -> Result<MultiQuery> {
        if let Ok(ip_network) = IpNetwork::from_str(domain_name) {
            Lookup::ptr_query(ip_network)
        } else {
            let domain_name = name_builder.from_str(domain_name)?;
            Lookup::name_query(domain_name, record_types)
        }
    }

    fn ptr_query(ip_network: IpNetwork) -> Result<MultiQuery> {
        let q = MultiQuery::multi_name(ip_network.iter(), RecordType::PTR).context("Failed to create query")?;
        info!("Prepared query for reverse lookups.");
        Ok(q)
    }

    fn name_query(name: Name, record_types: &[RecordType]) -> Result<MultiQuery> {
        let record_types_len = record_types.len();
        let q = MultiQuery::multi_record(name, record_types.to_vec()).context("Failed to build query")?;
        info!("Prepared query for name lookup for {} record types.", record_types_len);
        Ok(q)
    }
}

pub struct DnsLookups<'a> {
    env: Environment<'a, LookupConfig>,
    query: MultiQuery,
    app_resolver: AppResolver,
}

impl<'a> DnsLookups<'a> {
    pub async fn lookups(self) -> PartialResult<Whois<'a>> {
        self.env
            .console
            .print_partial_headers("Running lookups.", &self.app_resolver.resolvers(), &self.query);

        info!("Running lookups");
        let (lookups, run_time) = time(self.app_resolver.lookup(self.query)).await?;
        info!("Finished Lookups.");

        self.env
            .console
            .print_partial_results(&self.env.app_config.output_config, &lookups, run_time)?;

        Ok(Whois { env: self.env, lookups })
    }
}

pub struct Whois<'a> {
    env: Environment<'a, LookupConfig>,
    lookups: Lookups,
}

impl<'a> Whois<'a> {
    pub async fn optional_whois(self) -> PartialResult<LookupResult<'a>> {
        if self.env.mod_config.whois {
            self.whois().await
        } else {
            Ok(LookupResult {
                env: self.env,
                lookups: self.lookups,
                whois: None,
            })
        }
    }

    async fn whois(self) -> PartialResult<LookupResult<'a>> {
        let ip_addresses = Whois::ips_from_lookups(&self.lookups)?;
        let query_types = vec![QueryType::NetworkInfo, QueryType::GeoLocation, QueryType::Whois];
        let query = whois::MultiQuery::from_iter(ip_addresses, query_types);

        let opts = WhoisClientOpts::with_cache(8, self.env.app_config.abort_on_error, 1024, Duration::from_secs(60));
        let whois_client = WhoisClient::new(opts);

        if self.env.console.show_partial_headers() {
            self.env.console.caption("Running WHOIS queries.");
            self.env.console.print_whois_estimates(&query);
        }

        info!("Running Whois queries.");
        let (whois, run_time) = time(whois_client.query(query)).await?;
        info!("Finished queries.");

        self.env
            .console
            .print_partial_results(&self.env.app_config.output_config, &whois, run_time)?;

        Ok(LookupResult {
            env: self.env,
            lookups: self.lookups,
            whois: Some(whois),
        })
    }

    fn ips_from_lookups(lookups: &Lookups) -> Result<impl Iterator<Item = IpNetwork>> {
        // First, let's get the successful PTR responses. These contain the IP to Name queries which
        // have been successfully looked up. Then convert those IP address types.
        let ptrs: Vec<_> = lookups
            .iter()
            .filter(|x| x.result().is_response())
            .filter(|x| x.query().record_type == RecordType::PTR)
            .map(|x| x.query().name())
            .map(|x| x.to_ip_addr())
            .collect();
        let ptrs: crate::Result<Vec<_>> = ptrs.into_iter().collect();
        let ptrs = ptrs?;
        let ptrs: HashSet<IpAddr> = ptrs.into_iter().collect();

        // Second, check if the lookups contain any A or AAAA responses which point to IP addresses.
        let ips = lookups
            .a()
            .unique()
            .to_owned()
            .into_iter()
            .map(IpAddr::V4)
            .chain(lookups.aaaa().unique().to_owned().into_iter().map(IpAddr::V6))
            .map(IpNetwork::from);

        // At last, combine these two sets of IP addresses for the Whois lookup
        Ok(ptrs.into_iter().map(IpNetwork::from).chain(ips))
    }
}

pub struct LookupResult<'a> {
    env: Environment<'a, LookupConfig>,
    lookups: Lookups,
    whois: Option<WhoisResponses>,
}

impl<'a> LookupResult<'a> {
    pub fn output(self) -> PartialResult<ExitStatus> {
        match self.env.app_config.output {
            OutputType::Json => self.json_output(),
            OutputType::Summary => self.summary_output(),
        }
    }

    fn json_output(self) -> PartialResult<ExitStatus> {
        #[derive(Debug, Serialize)]
        struct Json {
            lookups: Lookups,
            whois: Option<WhoisResponses>,
        }
        impl SummaryFormatter for Json {
            fn output<W: Write>(&self, _: &mut W, _: &SummaryOptions) -> crate::Result<()> {
                unimplemented!()
            }
        }
        let data = Json {
            lookups: self.lookups,
            whois: self.whois,
        };

        output::output(&self.env.app_config.output_config, &data)?;
        Ok(ExitStatus::Ok)
    }

    fn summary_output(self) -> PartialResult<ExitStatus> {
        if self.env.console.not_quiet() {
            self.env.console.finished();
        }

        Ok(ExitStatus::Ok)
    }
}
