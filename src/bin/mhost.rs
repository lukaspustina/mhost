use anyhow::Result;
use log::debug;

use mhost::app::{run, setup_clap, start_logging_for_level, Config};
use std::convert::TryInto;

#[tokio::main]
async fn main() -> Result<()> {
    let args = setup_clap().get_matches();

    if args.is_present("no-color") {
        yansi::Paint::disable();
    }

    start_logging_for_level(args.occurrences_of("v"));
    debug!("Set up logging.");

    let config: Config = args.try_into()?;
    debug!("Parsed args.");

    let res = run(&config).await;
    debug!("Finished.");

    res
}
