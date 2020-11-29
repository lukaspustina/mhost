use std::convert::TryInto;

use anyhow::Result;
use log::info;

use mhost::app::cli::{list_predefined_nameservers, ExitStatus};
use mhost::app::logging::start_logging_for_level;
use mhost::app::modules;
use mhost::app::GlobalConfig;
use mhost::app::{app, global_config};
use mhost::output::styles::ERROR_PREFIX;

async fn run() -> Result<ExitStatus> {
    let args = app::app().get_matches();

    if args.is_present("no-color") {
        mhost::output::styles::no_color_mode();
    }
    if args.is_present("ascii") {
        mhost::output::styles::ascii_mode();
    }

    start_logging_for_level(args.occurrences_of("v"));
    info!("Set up logging.");

    let global_config: GlobalConfig = if let Ok(config) = (&args).try_into() {
        config
    } else {
        return Ok(ExitStatus::ConfigParsingFailed);
    };
    info!("Parsed global args.");

    if global_config.list_predefined {
        list_predefined_nameservers();
        return Ok(ExitStatus::Ok);
    }

    let res = match args.subcommand_name() {
        Some("discover") => modules::discover::run(&args, &global_config).await,
        Some("get-server-lists") => modules::get_server_lists::run(&args, &global_config).await,
        Some("lookup") => modules::lookup::run(&args, &global_config).await,
        Some("soa-check") => modules::soa_check::run(&args, &global_config).await,
        _ => {
            global_config::show_help();
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
