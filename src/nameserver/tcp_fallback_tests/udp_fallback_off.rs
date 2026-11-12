use hickory_resolver::config::ProtocolConfig;

use crate::nameserver::NameServerConfig;

// The conversion no longer depends on the fallback option: switching it off yields the same
// UDP-only config (the opt-out is the resolver's missing `tcp_retry`).
#[test]
fn udp_config_yields_only_udp_connection_regardless_of_fallback_opt_out() {
    let config = NameServerConfig::udp(([127, 0, 0, 1], 5353));

    let proto = config.to_proto();

    assert_eq!(proto.connections.len(), 1);
    assert!(matches!(proto.connections[0].protocol, ProtocolConfig::Udp));
    assert_eq!(proto.connections[0].port, 5353);
}
