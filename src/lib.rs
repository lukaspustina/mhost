// TODO: deny missing docs
#![allow(missing_docs)]

#[macro_use]
extern crate error_chain;
extern crate futures;
extern crate hyper;
extern crate tokio_core;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate trust_dns;

pub mod lookup;
pub mod statistics;
pub mod ungefiltert_surfen;

pub use lookup::{Query, Response, lookup, multiple_lookup};
pub use statistics::Statistics;
