use hickory_resolver::config::ProtocolConfig;

use crate::nameserver::NameServerConfig;

// A `tcp:` nameserver keeps exactly one TCP connection on its own port.
#[test]
fn tcp_nameserver_has_only_tcp_connection() {
    let proto = NameServerConfig::tcp(([127, 0, 0, 1], 5353)).to_proto();

    assert_eq!(proto.connections.len(), 1);
    assert!(matches!(proto.connections[0].protocol, ProtocolConfig::Tcp));
    assert_eq!(proto.connections[0].port, 5353);
}
