use clap::App;

pub mod download_server_lists;
pub mod lookup;
pub mod soa_check;

pub fn subcommands() -> Vec<App<'static, 'static>> {
    vec![
        download_server_lists::config::subcommand(),
        lookup::config::subcommand(),
        soa_check::config::subcommand()
    ]
        .into_iter()
        .map(|x|
            x
             .version(env!("CARGO_PKG_VERSION"))
             .author(env!("CARGO_PKG_AUTHORS"))
        )
        .collect()
}
