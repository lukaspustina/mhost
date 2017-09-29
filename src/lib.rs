// TODO: deny missing docs
#![allow(missing_docs)]

#[macro_use]
extern crate error_chain;
extern crate futures;
extern crate tokio_core;
extern crate trust_dns;

pub mod lookup;

pub use lookup::{Query, Response, lookup, multiple_lookup};