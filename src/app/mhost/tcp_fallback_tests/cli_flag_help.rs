// The global `--no-tcp-fallback` flag disables the TCP retry of truncated UDP answers for every
// resolver of the run (system and predefined nameservers alike) and says so in its help text.

use crate::app::mhost::app_config::AppConfig;
use crate::app::mhost::cli_parser::create_parser;
use crate::app::mhost::resolver::load_resolver_opts;

fn opts_tcp_fallback(argv: &[&str]) -> bool {
    let matches = create_parser().try_get_matches_from(argv).expect("arguments parse");
    let config = AppConfig::try_from(&matches).expect("app config builds");
    load_resolver_opts(&config).expect("resolver opts load").tcp_fallback
}

#[test]
fn no_tcp_fallback_flag_is_global_and_documents_truncation() {
    let cmd = create_parser();
    let arg = cmd
        .get_arguments()
        .find(|a| a.get_id() == "no-tcp-fallback")
        .expect("global arg no-tcp-fallback exists");
    assert!(arg.is_global_set(), "--no-tcp-fallback must be global");

    let help = [arg.get_help(), arg.get_long_help()]
        .into_iter()
        .flatten()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(help.contains("truncat"), "help must mention truncated answers: {help}");
    assert!(help.contains("TCP"), "help must mention TCP: {help}");
}

#[test]
fn no_tcp_fallback_flag_disables_tcp_fallback_in_resolver_opts() {
    let resolv_conf = std::env::temp_dir().join(format!("mhost-tcp-fallback-cli-{}.conf", std::process::id()));
    std::fs::write(&resolv_conf, "nameserver 127.0.0.1\noptions ndots:2\n").expect("write resolv.conf");
    let resolv_conf = resolv_conf.to_str().expect("utf-8 temp path").to_string();

    let cases: Vec<(Vec<&str>, bool)> = vec![
        (vec!["mhost", "-p", "lookup", "example.com"], true),
        (vec!["mhost", "--no-tcp-fallback", "-p", "lookup", "example.com"], false),
        (
            vec![
                "mhost",
                "--no-tcp-fallback",
                "--use-system-resolv-opt",
                "--resolv-conf",
                &resolv_conf,
                "-p",
                "lookup",
                "example.com",
            ],
            false,
        ),
        (
            vec![
                "mhost",
                "--use-system-resolv-opt",
                "--resolv-conf",
                &resolv_conf,
                "-p",
                "lookup",
                "example.com",
            ],
            true,
        ),
    ];

    let results: Vec<bool> = cases.iter().map(|(argv, _)| opts_tcp_fallback(argv)).collect();
    let _ = std::fs::remove_file(&resolv_conf);
    for ((argv, expected), got) in cases.iter().zip(results) {
        assert_eq!(got, *expected, "tcp_fallback for {argv:?}");
    }
}
