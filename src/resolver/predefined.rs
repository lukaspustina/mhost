use crate::nameserver::predefined;
use crate::resolver::ResolverConfig;

pub fn resolver_configs() -> Vec<ResolverConfig> {
    predefined::nameserver_configs().into_iter().map(From::from).collect()
}
