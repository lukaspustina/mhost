use anyhow::Result;
use log::info;

use mhost::app::{run, setup_clap, start_logging_for_level, Config};
use std::convert::TryInto;

#[tokio::main]
async fn main() -> Result<()> {
    let args = setup_clap().get_matches();

    if args.is_present("no-color") {
        yansi::Paint::disable();
    }

    start_logging_for_level(args.occurrences_of("v"));
    info!("Set up logging.");

    let config: Config = args.try_into()?;
    info!("Parsed args.");

    let res = run(&config).await;
    info!("Finished.");

    res
}
