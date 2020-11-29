use std::path::Path;
use std::time::Instant;

use anyhow::Result;
use log::info;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

use crate::app::cli::{print_estimates_downloads, print_statistics, ExitStatus};
use crate::app::modules::get_server_lists::config::DownloadServerListConfig;
use crate::app::{GlobalConfig, ModuleStep};
use crate::output::styles::{self, CAPTION_PREFIX, OK_PREFIX};
use crate::services::server_lists::{DownloadResponses, ServerListDownloader, ServerListDownloaderOpts};

pub struct GetServerLists {}

impl GetServerLists {
    pub fn init(global_config: &GlobalConfig, config: DownloadServerListConfig) -> Result<DownloadServerLists> {
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

        Ok(DownloadServerLists {
            global_config,
            config,
            downloader,
        })
    }
}

pub struct DownloadServerLists<'a> {
    global_config: &'a GlobalConfig,
    config: DownloadServerListConfig,
    downloader: ServerListDownloader,
}

impl<'a> DownloadServerLists<'a> {
    pub async fn download_server_lists(self) -> Result<ModuleStep<FileWriter<'a>>> {
        info!("Downloading lists");
        let start_time = Instant::now();
        let servers = self.downloader.download(self.config.server_list_specs).await?;
        let total_run_time = Instant::now() - start_time;
        info!("Finished downloads.");

        if !self.global_config.quiet {
            print_statistics(&servers, total_run_time);
        }

        Ok(ModuleStep::Next(FileWriter {
            global_config: self.global_config,
            output_file_path: self.config.output_file_path,
            servers,
        }))
    }
}

impl<'a> ModuleStep<FileWriter<'a>> {
    pub async fn write_servers_to_file(self) -> Result<ExitStatus> {
        match self {
            ModuleStep::Next(next) => next.write_servers_to_file().await,
            ModuleStep::ExitStatus(e) => Ok(e),
        }
    }
}

pub struct FileWriter<'a> {
    global_config: &'a GlobalConfig,
    output_file_path: String,
    servers: DownloadResponses,
}

impl<'a> FileWriter<'a> {
    async fn write_servers_to_file(self) -> Result<ExitStatus> {
        info!("Writing nameserver configs to file.");
        FileWriter::write_servers(&self.output_file_path, &self.servers).await?;
        info!("Finished writing.");

        if !self.global_config.quiet {
            println!("{} Saved to file '{}'.", &*OK_PREFIX, &self.output_file_path);
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
}
