use hickory_resolver::config::ProtocolConfig;

use crate::nameserver::NameServerConfig;
use crate::resolver::ResolverOpts;

// The TCP retry lives in the resolver, not in the hickory nameserver config: with fallback on
// (the default) the config still holds only the UDP connection.
#[test]
fn udp_with_fallback_on_still_yields_only_udp() {
    assert!(ResolverOpts::default().tcp_fallback);
    let config = NameServerConfig::udp(([127, 0, 0, 1], 5353));

    let proto = config.to_proto();

    assert_eq!(proto.connections.len(), 1);
    assert!(matches!(proto.connections[0].protocol, ProtocolConfig::Udp));
    assert_eq!(proto.connections[0].port, 5353);
}
