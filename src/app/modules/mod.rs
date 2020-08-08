use clap::App;

pub mod lookup;
pub mod soa_check;

pub fn subcommands() -> Vec<App<'static, 'static>> {
    vec![lookup::config::subcommand(), soa_check::config::subcommand()]
}