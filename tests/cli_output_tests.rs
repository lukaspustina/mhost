use lit;
use std::env;

const CRATE_PATH: &'static str = env!("CARGO_MANIFEST_DIR");
const DEBUG_TARGET_PATH: &'static str = "target/debug";

fn mhost_bin() -> String {
    format!("{}/{}/mhost{}", CRATE_PATH, DEBUG_TARGET_PATH, env::consts::EXE_SUFFIX)
}

#[test]
fn cli_output_tests() {
    lit::run::tests(lit::event_handler::Default::default(), |config| {
        config.add_search_path("tests/lit");
        config.add_extension("output");
        config.constants.insert("mhost_bin".to_owned(), mhost_bin());
        config
            .constants
            .insert("mhost_version".to_owned(), env!("CARGO_PKG_VERSION").to_owned());
    })
    .expect("cli output tests failed");
}
