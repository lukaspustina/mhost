use hickory_resolver::config::ProtocolConfig;

use crate::nameserver::NameServerConfig;

#[test]
fn udp_config_with_fallback_off_has_only_udp_connection() {
    let config = NameServerConfig::udp(([127, 0, 0, 1], 5353));

    let proto = config.to_proto(false);

    assert_eq!(proto.connections.len(), 1);
    assert!(matches!(proto.connections[0].protocol, ProtocolConfig::Udp));
    assert_eq!(proto.connections[0].port, 5353);
}
