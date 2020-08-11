use std::convert::TryInto;

use anyhow::Result;
use log::info;

use mhost::app::cli::list_predefined_nameservers;
use mhost::app::global_config;
use mhost::app::GlobalConfig;
use mhost::app::logging::start_logging_for_level;
use mhost::app::modules;

#[tokio::main]
async fn main() -> Result<()> {
    let args = global_config::setup_clap().get_matches();

    if args.is_present("no-color") {
        mhost::output::styles::no_color_mode();
    }
    if args.is_present("ascii") {
        mhost::output::styles::ascii_mode();
    }

    start_logging_for_level(args.occurrences_of("v"));
    info!("Set up logging.");

    let global_config: GlobalConfig = (&args).try_into()?;
    info!("Parsed global args.");

    if global_config.list_predefined {
        list_predefined_nameservers();
        return Ok(());
    }

    let res = match args.subcommand_name() {
        Some("lookup") => modules::lookup::run(&args, &global_config).await,
        Some("soa-check") => modules::soa_check::run(&args, &global_config).await,
        _ => Ok(()),
    };
    info!("Finished.");

    res
}
