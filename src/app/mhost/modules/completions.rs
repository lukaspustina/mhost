// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use anyhow::Result;
use clap::ArgMatches;

use crate::app::{cli_parser, ExitStatus};

pub fn run(args: &ArgMatches) -> Result<ExitStatus> {
    let args = args.subcommand_matches("completions").unwrap();
    let shell = args.get_one::<clap_complete::Shell>("shell").unwrap();
    let mut cmd = cli_parser::create_parser();
    clap_complete::generate(*shell, &mut cmd, "mhost", &mut std::io::stdout());
    Ok(ExitStatus::Ok)
}
