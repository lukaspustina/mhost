use crate::app::GlobalConfig;
use anyhow::Result;
use clap::ArgMatches;
use log::info;
use std::time::Instant;
use crate::app::modules::download_server_lists::config::DownloadServerListConfig;
use std::convert::TryInto;
use crate::app::cli::{ExitStatus, print_statistics, print_estimates_downloads};
use crate::output::styles::{self, CAPTION_PREFIX, OK_PREFIX};
use crate::services::server_lists::{ServerListDownloaderOpts, ServerListDownloader, DownloadResponses};
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

pub mod config;

pub async fn run(args: &ArgMatches<'_>, global_config: &GlobalConfig) -> Result<ExitStatus> {
    info!("download-server-lists module selected.");
    let args = args.subcommand_matches("download-server-lists").unwrap();
    let config: DownloadServerListConfig = args.try_into()?;
    download_server_lists(&global_config, config).await
}

pub async fn download_server_lists(global_config: &GlobalConfig, config: DownloadServerListConfig) -> Result<ExitStatus> {
    let opts: ServerListDownloaderOpts = ServerListDownloaderOpts::new(global_config.max_concurrent_requests, global_config.abort_on_error);
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