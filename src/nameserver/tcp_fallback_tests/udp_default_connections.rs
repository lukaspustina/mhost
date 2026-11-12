use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_resolver::config::ProtocolConfig;

use crate::nameserver::NameServerConfig;
use crate::resolver::ResolverOpts;

#[test]
fn udp_nameserver_default_gets_udp_then_tcp_on_its_port() {
    // (config, expected ip, expected port)
    let cases: Vec<(NameServerConfig, IpAddr, u16)> = vec![
        (
            NameServerConfig::udp((Ipv4Addr::LOCALHOST, 5353)),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            5353,
        ),
        (
            NameServerConfig::udp((Ipv4Addr::LOCALHOST, 5454)),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            5454,
        ),
        (
            NameServerConfig::udp((Ipv6Addr::LOCALHOST, 5353)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            5353,
        ),
    ];

    for (config, ip, port) in cases {
        let proto = config.to_proto(ResolverOpts::default().tcp_fallback);

        assert_eq!(proto.ip, ip);
        assert_eq!(proto.connections.len(), 2, "connections for {ip}:{port}");
        assert!(
            matches!(proto.connections[0].protocol, ProtocolConfig::Udp),
            "first connection for {ip}:{port} must be UDP"
        );
        assert_eq!(proto.connections[0].port, port);
        assert!(
            matches!(proto.connections[1].protocol, ProtocolConfig::Tcp),
            "second connection for {ip}:{port} must be TCP"
        );
        assert_eq!(proto.connections[1].port, port);
    }
}
