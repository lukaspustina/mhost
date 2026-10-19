//! Checks over `website/`, the documentation site's sources. They live in the library's test tree
//! because `just adlc-verify` runs only `cargo test --lib` and `--doc`.

mod config;
mod copy;
mod package;
mod readme;
mod repo;
