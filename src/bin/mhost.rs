use std::convert::TryInto;

use anyhow::Result;
use log::info;

use mhost::app::cli_parser;
use mhost::app::console::{list_predefined_nameservers, ExitStatus};
use mhost::app::logging::start_logging_for_level;
use mhost::app::modules;
use mhost::app::AppConfig;
use mhost::output::styles::ERROR_PREFIX;

async fn run() -> Result<ExitStatus> {
    let args = cli_parser::create_parser().get_matches();

    if args.is_present("no-color") {
        mhost::output::styles::no_color_mode();
    }
    if args.is_present("ascii") {
        mhost::output::styles::ascii_mode();
    }

    start_logging_for_level(args.occurrences_of("v"));
    info!("Set up logging.");

    let app_config: AppConfig = if let Ok(config) = (&args).try_into() {
        config
    } else {
        return Ok(ExitStatus::ConfigParsingFailed);
    };
    info!("Parsed global args.");

    if app_config.list_predefined {
        list_predefined_nameservers();
        return Ok(ExitStatus::Ok);
    }

    let res = match args.subcommand_name() {
        Some("discover") => modules::discover::run(&args, &app_config).await,
        Some("get-server-lists") => modules::get_server_lists::run(&args, &app_config).await,
        Some("lookup") => modules::lookup::run(&args, &app_config).await,
        Some("soa-check") => modules::soa_check::run(&args, &app_config).await,
        _ => {
            cli_parser::show_help();
            Ok(ExitStatus::Ok)
        }
    };
    info!("Finished.");

    res
}

#[tokio::main]
async fn main() {
    let res = run().await;

    let exit_status = match res {
        Ok(exit_status) => exit_status,
        Err(err) => {
            eprintln!("{} Failed: {:#}", &*ERROR_PREFIX, err);
            ExitStatus::Failed
        }
    };

    std::process::exit(exit_status as i32);
}
