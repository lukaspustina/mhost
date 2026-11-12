use std::net::SocketAddr;

use hickory_resolver::config::ProtocolConfig;

use crate::nameserver::NameServerConfig;
use crate::resolver::ResolverOpts;

fn udp_ns() -> NameServerConfig {
    NameServerConfig::udp("127.0.0.1:5353".parse::<SocketAddr>().unwrap())
}

// `tcp_fallback` is on by default; the hickory nameserver of a `udp:` config carries UDP only,
// the TCP retry lives in a separate resolver.
#[test]
fn default_opts_hand_udp_only_to_hickory() {
    let opts = ResolverOpts::default();
    assert!(opts.tcp_fallback);

    let proto = udp_ns().to_proto();

    assert_eq!(proto.connections.len(), 1);
    assert!(matches!(proto.connections[0].protocol, ProtocolConfig::Udp));
}

// The hickory connections of a `udp:` config do not depend on the flag.
#[test]
fn disabled_tcp_fallback_hands_udp_only_to_hickory() {
    let opts = ResolverOpts {
        tcp_fallback: false,
        ..Default::default()
    };
    assert!(!opts.tcp_fallback);

    let proto = udp_ns().to_proto();

    assert_eq!(proto.connections.len(), 1);
    assert!(matches!(proto.connections[0].protocol, ProtocolConfig::Udp));
    assert_eq!(proto.connections[0].port, 5353);
}

// Opts read from a system resolv.conf keep the TCP fallback on.
#[test]
fn opts_from_system_config_have_tcp_fallback() {
    let dir = std::env::temp_dir().join(format!("mhost-tcp-fallback-opts-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("resolv.conf");
    std::fs::write(&path, "nameserver 127.0.0.1\n").expect("write resolv.conf");

    let opts = ResolverOpts::from_system_config_path(&path);
    std::fs::remove_dir_all(&dir).ok();

    assert!(opts.expect("opts").tcp_fallback);
}
