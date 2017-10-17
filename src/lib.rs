// TODO: deny missing docs
#![allow(missing_docs)]
// Ignore Clippy lints
#![allow(unknown_lints)]

#[cfg(feature = "bin")]
extern crate ansi_term;
#[macro_use]
extern crate error_chain;
extern crate futures;
extern crate hyper;
#[cfg(feature = "bin")]
extern crate itertools;
extern crate tokio_core;
extern crate resolv_conf;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
#[cfg(feature = "bin")]
extern crate tabwriter;
extern crate trust_dns;

#[cfg(feature = "bin")]
pub mod get;
pub mod lookup;
#[cfg(feature = "bin")]
pub mod output;
pub mod statistics;
pub mod ungefiltert_surfen;

pub use lookup::{Query, Response, lookup, multiple_lookup};
pub use statistics::Statistics;
