// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use clap_complete::Shell;
use std::env;
use std::fs;
use std::process;

#[allow(dead_code)]
#[path = "src/app/mhost/cli_parser.rs"]
mod cli_parser;

fn main() {
    // OUT_DIR is set by Cargo and is the only place which is allowed to be written to during compilation for 'cargo publihs' and docs.rs.
    let output_dir = match env::var_os("OUT_DIR") {
        Some(outdir) => outdir,
        None => {
            eprintln!("Cargo output directory environment variable is not set: Cannot continue. Aborting");
            process::exit(1);
        }
    };
    fs::create_dir_all(&output_dir).expect("failed to create output directory");

    // The website checks (src/website_tests/) read the repository around the crate; a packaged
    // crate has neither them nor the justfile, so they compile only in a repository checkout.
    println!("cargo::rustc-check-cfg=cfg(mhost_repo)");
    if fs::metadata("justfile").is_ok() {
        println!("cargo::rustc-cfg=mhost_repo");
    }

    // Create Shell completions
    let mut cmd = cli_parser::create_parser();
    clap_complete::generate_to(Shell::Bash, &mut cmd, "mhost", &output_dir)
        .expect("failed to generate Bash completions");
    clap_complete::generate_to(Shell::Fish, &mut cmd, "mhost", &output_dir)
        .expect("failed to generate Fish completions");
    clap_complete::generate_to(Shell::Zsh, &mut cmd, "mhost", &output_dir).expect("failed to generate Zsh completions");
}
