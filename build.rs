// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use clap::Shell;
use std::env;
use std::fs;
use std::path::Path;

#[allow(dead_code)]
#[path = "src/app/cli_parser.rs"]
mod cli_parser;

fn main() {
    let root_dir = env::var_os("CARGO_MANIFEST_DIR").expect("Cargo output directory environment variable is not set.");
    let output_dir = Path::new(&root_dir).join("contrib").join("shell-completions");
    fs::create_dir_all(&output_dir).expect("failed to create output directory");

    // Create Shell completions
    let mut parser = cli_parser::create_parser();
    parser.gen_completions("mhost", Shell::Bash, &output_dir);
    parser.gen_completions("mhost", Shell::Fish, &output_dir);
    parser.gen_completions("mhost", Shell::Zsh, &output_dir);
}
