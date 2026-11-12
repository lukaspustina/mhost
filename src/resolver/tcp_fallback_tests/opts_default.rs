use crate::resolver::ResolverOpts;

// TCP fallback for truncated UDP answers is on unless the caller turns it off.
#[test]
fn default_resolver_opts_enable_tcp_fallback() {
    assert!(ResolverOpts::default().tcp_fallback);
}
