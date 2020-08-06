use std::convert::TryInto;

use anyhow::Result;
use log::info;

use mhost::app::{GlobalConfig, list_predefined_nameservers, lookup, LookupConfig, setup_clap, start_logging_for_level};

#[tokio::main]
async fn main() -> Result<()> {
    let args = setup_clap().get_matches();

    if args.is_present("no-color") {
        yansi::Paint::disable();
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
        Some("lookup") => {
            info!("lookup module selected.");
            let args = args.subcommand_matches("lookup").unwrap();
            let config: LookupConfig = args.try_into()?;
            lookup::run(&global_config, &config).await
        }
        _ => Ok(())
    };
    info!("Finished.");

    res
}
