use crate::app::cli::{print_estimates_downloads, print_statistics, ExitStatus};
use crate::app::modules::get_server_lists::config::DownloadServerListConfig;
use crate::app::GlobalConfig;
use crate::output::styles::{self, CAPTION_PREFIX, OK_PREFIX};
use crate::services::server_lists::{DownloadResponses, ServerListDownloader, ServerListDownloaderOpts};
use anyhow::Result;
use clap::ArgMatches;
use log::info;
use std::convert::TryInto;
use std::path::Path;
use std::time::Instant;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

pub mod config;

pub async fn run(args: &ArgMatches<'_>, global_config: &GlobalConfig) -> Result<ExitStatus> {
    info!("get-server-lists module selected.");
    let args = args.subcommand_matches("get-server-lists").unwrap();
    let config: DownloadServerListConfig = args.try_into()?;
    download_server_lists(&global_config, config).await
}

pub async fn download_server_lists(
    global_config: &GlobalConfig,
    config: DownloadServerListConfig,
) -> Result<ExitStatus> {
    let opts: ServerListDownloaderOpts =
        ServerListDownloaderOpts::new(global_config.max_concurrent_requests, global_config.abort_on_error);
    let downloader = ServerListDownloader::new(opts);

    if !global_config.quiet {
        println!(
            "{}",
            styles::EMPH.paint(format!("{} Downloading server lists.", &*CAPTION_PREFIX))
        );
        print_estimates_downloads(&config.server_list_specs);
    }

    info!("Downloading lists");
    let start_time = Instant::now();
    let servers = downloader.download(config.server_list_specs).await?;
    let total_run_time = Instant::now() - start_time;
    info!("Finished downloads.");

    if !global_config.quiet {
        print_statistics(&servers, total_run_time);
    }

    info!("Writing nameserver configs to file.");
    write_servers(&config.output_file_path, &servers).await?;
    info!("Finished writing.");

    if !global_config.quiet {
        println!("{} Saved to file '{}'.", &*OK_PREFIX, &config.output_file_path);
    }

    Ok(ExitStatus::Ok)
}

async fn write_servers<P: AsRef<Path>>(path: P, response: &DownloadResponses) -> Result<()> {
    let mut file = File::create(path).await?;

    for config in response.nameserver_configs() {
        let str = format!("{}\n", config.to_string());
        file.write(str.as_bytes()).await?;
    }

    Ok(())
}
