use crate::app::GlobalConfig;
use crate::resolver::{ResolverGroup, UniQuery, MultiQuery, ResolverConfig};
use anyhow::Result;
use crate::RecordType;
use crate::estimate::Estimate;
use crate::resolver::lookup::Uniquify;
use crate::nameserver::NameServerConfig;
use crate::app::config::SoaCheckConfig;

pub async fn run(_global_config: &GlobalConfig, config: &SoaCheckConfig) -> Result<()> {
    let name = config.domain_name.clone();
    let resolvers = ResolverGroup::from_system_config(Default::default()).await?;

    let q = UniQuery::new(name.clone(), RecordType::NS)?;
    println!(
        "Sending {} requests for names of authoritative name servers.",
        resolvers.estimate(&q.clone().into())
    );
    let authoritative_name_server_names = resolvers.lookup(q).await.unwrap().ns().unique().to_owned();

    let q =
        MultiQuery::multi_name(authoritative_name_server_names, RecordType::A)?;
    println!(
        "Sending {} requests for IPv4 addresses of authoritative name servers.",
        resolvers.estimate(&q)
    );
    let authoritative_name_server_ips = resolvers.lookup(q).await.unwrap().a().unique().to_owned();

    let authoritative_name_servers = authoritative_name_server_ips
        .into_iter()
        .map(|ip| NameServerConfig::udp((ip, 53)))
        .map(ResolverConfig::new);
    let resolvers = ResolverGroup::from_configs(authoritative_name_servers, Default::default(), Default::default()).await?;

    let q = UniQuery::new(name, RecordType::SOA)?;
    println!(
        "Sending {} requests for SOA records of authoritative name servers.",
        resolvers.estimate(&q.clone().into())
    );
    let soas = resolvers.lookup(q).await.unwrap().soa().unique().to_owned();
    println!("SOAs -- should be exactly one: {:#?}", &soas);

    Ok(())
}
