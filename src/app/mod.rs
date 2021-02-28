// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! `mhost` command line app to query, discover and lint DNS.
pub mod app_config;
pub mod cli_parser;
pub mod console;
pub mod logging;
pub mod modules;
pub mod output;
pub mod resolver;
pub mod utils;

pub use app_config::AppConfig;

/// `ExitStatus` represents the exit states that will be return to the OS after termination
#[derive(Debug, Clone)]
pub enum ExitStatus {
    /// All fine.
    Ok = 0,
    /// CLI argument parsing failed.
    CliParsingFailed = 1,
    /// Processing of CLI arguments failed.
    ConfigParsingFailed = 2,
    /// An unrecoverable error occurred. This is worst case and should not happen.
    UnrecoverableError = 3,
    /// A module failed to properly execute.
    Failed = 10,
    /// A module check failed.
    CheckFailed = 11,
    /// A module could not proceed because of invalid preconditions of the succeeding step.
    Abort = 12,
}

/* Unstable :(
use std::process::Termination;
impl Termination for ExitStatus {
    fn report(self) -> i32 {
        self as i32
    }
}
*/
