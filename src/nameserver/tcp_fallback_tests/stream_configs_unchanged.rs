use std::net::SocketAddr;

use hickory_resolver::config::ProtocolConfig;

use crate::nameserver::NameServerConfig;

fn addr() -> SocketAddr {
    "127.0.0.1:5353".parse().unwrap()
}

#[test]
fn stream_configs_keep_exactly_one_connection_of_their_own_protocol() {
    type Check = fn(&ProtocolConfig) -> bool;
    let mut cases: Vec<(&str, NameServerConfig, Check)> = vec![("tcp", NameServerConfig::tcp(addr()), |p| {
        matches!(p, ProtocolConfig::Tcp)
    })];
    #[cfg(feature = "dot")]
    cases.push(("tls", NameServerConfig::tls(addr(), "dns.example.com"), |p| {
        matches!(p, ProtocolConfig::Tls { .. })
    }));
    #[cfg(feature = "doh")]
    cases.push(("https", NameServerConfig::https(addr(), "dns.example.com"), |p| {
        matches!(p, ProtocolConfig::Https { .. })
    }));

    for (name, config, is_own_protocol) in cases {
        for tcp_fallback in [true, false] {
            let proto = config.to_proto(tcp_fallback);
            assert_eq!(
                proto.connections.len(),
                1,
                "{name} with tcp_fallback={tcp_fallback} must keep exactly one connection"
            );
            let connection = &proto.connections[0];
            assert!(
                is_own_protocol(&connection.protocol),
                "{name} with tcp_fallback={tcp_fallback} must keep its own protocol"
            );
            assert_eq!(
                connection.port, 5353,
                "{name} with tcp_fallback={tcp_fallback} must keep the config's port"
            );
        }
    }
}
