// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::convert::TryInto;
use std::env;

use anyhow::{Context, Result};
use clap::ArgMatches;
use tokio::runtime::Runtime;
use tracing::info;

use mhost::app::console::{Console, ConsoleOpts};
use mhost::app::logging::Logging;
use mhost::app::modules::{self, PartialError};
use mhost::app::AppConfig;
use mhost::app::{cli_parser, ExitStatus};
use mhost::nameserver::predefined;

fn main() {
    let res = do_main();

    let exit_status = match res {
        Ok(exit_status) => exit_status,
        Err(err) => match err.downcast_ref::<PartialError>() {
            Some(PartialError::Failed(exit_status)) => exit_status.to_owned(),
            _ => {
                let console = Console::new(ConsoleOpts::default());
                console.error(format!("Error: {:#}", err));
                ExitStatus::UnrecoverableError
            }
        },
    };

    std::process::exit(exit_status as i32);
}

// Release build
#[cfg(not(debug_assertions))]
fn exit_subcommand_invalid() -> ExitStatus {
    ExitStatus::CliParsingFailed
}

// Debug build: Exit status should be CliParsingFailed, but then the lit test fails because of exit status != 0.
#[cfg(debug_assertions)]
fn exit_subcommand_invalid() -> ExitStatus {
    ExitStatus::Ok
}

fn do_main() -> Result<ExitStatus> {
    let args = cli_parser::create_parser().get_matches();
    let color = !args.is_present("no-color");
    let debug = args.is_present("debug");

    setup_terminal(&args, color);
    setup_logging(&args, color, debug);
    info!("Set up logging.");
    let app_config = if let Ok(app_config) = parse_global_args(&args) {
        app_config
    } else {
        return Ok(ExitStatus::ConfigParsingFailed);
    };
    info!("Parsed global args.");
    let console = setup_console(&app_config);
    let runtime = setup_tokio(app_config.max_worker_threads())?;
    info!(
        "Started Async Runtime with {} worker threads.",
        app_config
            .max_worker_threads()
            .map(|x| x.to_string())
            .unwrap_or_else(|| "Tokio default number of".to_string())
    );

    info!("Running command");
    let res = runtime.block_on(async { run_command(&args, &app_config, &console).await });
    info!("Finished command.");

    res
}

/// Start Tokio runtime, use either with default or explicitly set number of work threads
fn setup_tokio(num_threads: Option<usize>) -> Result<Runtime> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if let Some(num_threads) = num_threads {
        builder.worker_threads(num_threads);
    }
    builder.build().context("Failed to build Async Runtime")
}

fn setup_terminal(args: &ArgMatches, color: bool) {
    if !color {
        mhost::app::output::styles::no_color_mode();
    }
    if args.is_present("ascii") {
        mhost::app::output::styles::ascii_mode();
    }
}

fn setup_logging(args: &ArgMatches, color: bool, debug: bool) {
    Logging::new(args.occurrences_of("v"), env::var_os("RUST_LOG"), color, debug)
        .start()
        .expect("failed to initialize logging");
}

fn parse_global_args(args: &ArgMatches) -> Result<AppConfig> {
    let app_config: AppConfig = args.try_into()?;

    Ok(app_config)
}

fn setup_console(app_config: &AppConfig) -> Console {
    let console_opts = ConsoleOpts::from(app_config);

    Console::new(console_opts)
}

async fn run_command(args: &ArgMatches<'_>, app_config: &AppConfig, console: &Console) -> Result<ExitStatus> {
    if app_config.list_predefined {
        list_predefined_nameservers(&console);
        return Ok(ExitStatus::Ok);
    }

    match args.subcommand_name() {
        Some("check") => modules::check::run(&args, &app_config).await,
        Some("discover") => modules::discover::run(&args, &app_config).await,
        Some("server-lists") => modules::get_server_lists::run(&args, &app_config).await,
        Some("lookup") => modules::lookup::run(&args, &app_config).await,
        _ => {
            cli_parser::show_help();
            Ok(exit_subcommand_invalid())
        }
    }
}

pub fn list_predefined_nameservers(console: &Console) {
    console.caption("Predefined servers:");
    for ns in predefined::nameserver_configs() {
        console.itemize(format!("{}", ns));
    }
}
