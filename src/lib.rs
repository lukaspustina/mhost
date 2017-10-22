// TODO: deny missing docs
#![allow(missing_docs)]
// Ignore Clippy lints
#![allow(unknown_lints)]

#[cfg(feature = "bin")]
extern crate ansi_term;
#[cfg(feature = "bin")]
extern crate chrono;
#[cfg(feature = "bin")]
extern crate chrono_humanize;
#[macro_use]
extern crate error_chain;
extern crate futures;
extern crate hyper;
#[cfg(feature = "bin")]
extern crate itertools;
#[macro_use]
extern crate nom;
extern crate tokio_core;
#[cfg(feature = "bin")]
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
pub mod txt_records;
pub mod ungefiltert_surfen;

pub use lookup::{Query, Response, lookup, multiple_lookup};
pub use statistics::Statistics;
