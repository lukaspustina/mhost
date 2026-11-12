use hickory_resolver::config::ProtocolConfig;

use crate::nameserver::NameServerConfig;

#[test]
fn udp_with_fallback_on_yields_udp_then_tcp_on_same_port() {
    let config = NameServerConfig::udp(([127, 0, 0, 1], 5353));

    let proto = config.to_proto(true);

    assert_eq!(proto.connections.len(), 2);
    assert!(matches!(proto.connections[0].protocol, ProtocolConfig::Udp));
    assert_eq!(proto.connections[0].port, 5353);
    assert!(matches!(proto.connections[1].protocol, ProtocolConfig::Tcp));
    assert_eq!(proto.connections[1].port, 5353);
}
