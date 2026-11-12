use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_resolver::config::ProtocolConfig;

use crate::nameserver::NameServerConfig;

#[test]
fn udp_nameserver_gets_only_udp_on_its_port() {
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
        let proto = config.to_proto();

        assert_eq!(proto.ip, ip);
        assert_eq!(proto.connections.len(), 1, "connections for {ip}:{port}");
        assert!(
            matches!(proto.connections[0].protocol, ProtocolConfig::Udp),
            "the only connection for {ip}:{port} must be UDP"
        );
        assert_eq!(proto.connections[0].port, port);
    }
}
