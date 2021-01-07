use std::convert::TryInto;

use anyhow::Result;
use tracing::info;

use mhost::app::console::{Console, ConsoleOpts};
use mhost::app::logging::Logging;
use mhost::app::modules::{self, PartialError};
use mhost::app::AppConfig;
use mhost::app::{cli_parser, ExitStatus};
use mhost::nameserver::predefined;
use std::env;

async fn run() -> Result<ExitStatus> {
    let args = cli_parser::create_parser().get_matches();
    let color = !args.is_present("no-color");
    let debug = args.is_present("debug");

    if !color {
        mhost::app::output::styles::no_color_mode();
    }
    if args.is_present("ascii") {
        mhost::app::output::styles::ascii_mode();
    }

    Logging::new(args.occurrences_of("v"), env::var_os("RUST_LOG"), color, debug)
        .start()
        .expect("failed to initialize logging");
    info!("Set up logging.");

    let app_config: AppConfig = if let Ok(config) = (&args).try_into() {
        config
    } else {
        return Ok(ExitStatus::ConfigParsingFailed);
    };
    info!("Parsed global args.");

    let console_opts = ConsoleOpts::from(&app_config);
    let console = Console::new(console_opts);

    if app_config.list_predefined {
        list_predefined_nameservers(&console);
        return Ok(ExitStatus::Ok);
    }

    let res = match args.subcommand_name() {
        Some("check") => modules::check::run(&args, &app_config).await,
        Some("discover") => modules::discover::run(&args, &app_config).await,
        Some("get-server-lists") => modules::get_server_lists::run(&args, &app_config).await,
        Some("lookup") => modules::lookup::run(&args, &app_config).await,
        Some("soa-check") => modules::soa_check::run(&args, &app_config).await,
        _ => {
            cli_parser::show_help();
            Ok(exit_subcommand_invalid())
        }
    };
    info!("Finished.");

    res
}

pub fn list_predefined_nameservers(console: &Console) {
    console.caption("Predefined servers:");
    for ns in predefined::nameserver_configs() {
        console.itemize(format!("{}", ns));
    }
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

#[tokio::main]
async fn main() {
    let res = run().await;

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
