use std::path::Path;
use std::time::Instant;

use anyhow::{anyhow, Result};
use log::info;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

use crate::app::console::{print_estimates_downloads, print_statistics, ExitStatus};
use crate::app::modules::get_server_lists::config::DownloadServerListConfig;
use crate::app::modules::Partial;
use crate::app::AppConfig;
use crate::output::styles::{self, CAPTION_PREFIX, OK_PREFIX};
use crate::output::OutputType;
use crate::services::server_lists::{DownloadResponses, ServerListDownloader, ServerListDownloaderOpts};

pub struct GetServerLists {}

impl GetServerLists {
    pub fn init(app_config: &AppConfig, config: DownloadServerListConfig) -> Result<DownloadServerLists> {
        if app_config.output == OutputType::Json {
            return Err(anyhow!("JSON output is not support"));
        }

        let opts: ServerListDownloaderOpts =
            ServerListDownloaderOpts::new(app_config.max_concurrent_requests, app_config.abort_on_error);
        let downloader = ServerListDownloader::new(opts);

        Ok(DownloadServerLists {
            app_config,
            config,
            downloader,
        })
    }
}

pub struct DownloadServerLists<'a> {
    app_config: &'a AppConfig,
    config: DownloadServerListConfig,
    downloader: ServerListDownloader,
}

impl<'a> DownloadServerLists<'a> {
    pub async fn download_server_lists(self) -> Result<Partial<FileWriter<'a>>> {
        if !self.app_config.quiet {
            println!(
                "{}",
                styles::EMPH.paint(format!("{} Downloading server lists.", &*CAPTION_PREFIX))
            );
            print_estimates_downloads(&self.config.server_list_specs);
        }

        info!("Downloading lists");
        let start_time = Instant::now();
        let servers = self.downloader.download(self.config.server_list_specs).await?;
        let total_run_time = Instant::now() - start_time;
        info!("Finished downloads.");

        if !self.app_config.quiet {
            print_statistics(&servers, total_run_time);
        }

        Ok(Partial::Next(FileWriter {
            app_config: self.app_config,
            output_file_path: self.config.output_file_path,
            servers,
        }))
    }
}

impl<'a> Partial<FileWriter<'a>> {
    pub async fn write_servers_to_file(self) -> Result<ExitStatus> {
        match self {
            Partial::Next(next) => next.write_servers_to_file().await,
            Partial::ExitStatus(e) => Ok(e),
        }
    }
}

pub struct FileWriter<'a> {
    app_config: &'a AppConfig,
    output_file_path: String,
    servers: DownloadResponses,
}

impl<'a> FileWriter<'a> {
    async fn write_servers_to_file(self) -> Result<ExitStatus> {
        info!("Writing nameserver configs to file.");
        FileWriter::write_servers(&self.output_file_path, &self.servers).await?;
        info!("Finished writing.");

        if !self.app_config.quiet {
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
