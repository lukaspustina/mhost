use std::convert::TryInto;

use anyhow::Result;
use log::info;

use mhost::app::{GlobalConfig, list_predefined_nameservers, lookup, LookupConfig, setup_clap, start_logging_for_level, soa_check, SoaCheckConfig};

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
        },
        Some("soa-check") => {
            info!("soa-check module selected.");
            let args = args.subcommand_matches("soa-check").unwrap();
            let config: SoaCheckConfig = args.try_into()?;
            soa_check::run(&global_config, &config).await
        },
        _ => Ok(()),
    };
    info!("Finished.");

    res
}
