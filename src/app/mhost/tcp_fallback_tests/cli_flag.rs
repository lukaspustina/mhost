use crate::app::cli_parser::create_parser;
use crate::app::resolver::load_resolver_opts;
use crate::app::AppConfig;

fn tcp_fallback_for(args: &[&str]) -> bool {
    let matches = create_parser()
        .try_get_matches_from(args)
        .expect("CLI arguments must parse");
    let config = AppConfig::try_from(&matches).expect("AppConfig must build");
    load_resolver_opts(&config).expect("resolver opts must load").tcp_fallback
}

#[test]
fn no_tcp_fallback_flag_controls_resolver_opts() {
    let cases: [(&[&str], bool); 2] = [
        (&["mhost", "--no-tcp-fallback", "lookup", "example.com"], false),
        (&["mhost", "lookup", "example.com"], true),
    ];
    for (args, expected) in cases {
        assert_eq!(tcp_fallback_for(args), expected, "args: {:?}", args);
    }
}
