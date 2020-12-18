use std::path::Path;
use std::time::Instant;

use anyhow::{anyhow, Result};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tracing::info;

use crate::app::console::Console;
use crate::app::modules::get_server_lists::config::DownloadServerListConfig;
use crate::app::modules::{Environment, PartialResult};
use crate::app::output::OutputType;
use crate::app::{AppConfig, ExitStatus};
use crate::services::server_lists::{DownloadResponses, ServerListDownloader, ServerListDownloaderOpts};

pub struct GetServerLists {}

impl GetServerLists {
    pub fn init<'a>(
        app_config: &'a AppConfig,
        config: &'a DownloadServerListConfig,
    ) -> PartialResult<DownloadServerLists<'a>> {
        if app_config.output == OutputType::Json {
            return Err(anyhow!("JSON output is not support").into());
        }
        let console = Console::new(app_config);
        let env = Environment::new(app_config, config, console);

        let opts: ServerListDownloaderOpts =
            ServerListDownloaderOpts::new(app_config.max_concurrent_requests, app_config.abort_on_error);
        let downloader = ServerListDownloader::new(opts);

        Ok(DownloadServerLists { env, downloader })
    }
}

pub struct DownloadServerLists<'a> {
    env: Environment<'a, DownloadServerListConfig>,
    downloader: ServerListDownloader,
}

impl<'a> DownloadServerLists<'a> {
    pub async fn download_server_lists(self) -> PartialResult<FileWriter<'a>> {
        if self.env.console.not_quiet() {
            self.env.console.caption("Downloading server lists.");
            self.env
                .console
                .print_estimates_downloads(&self.env.mod_config.server_list_specs);
        }

        info!("Downloading lists");
        let start_time = Instant::now();
        let servers = self
            .downloader
            .download(self.env.mod_config.server_list_specs.clone())
            .await?;
        let total_run_time = Instant::now() - start_time;
        info!("Finished downloads.");

        if self.env.console.not_quiet() {
            self.env.console.print_statistics(&servers, total_run_time);
        }

        Ok(FileWriter { env: self.env, servers })
    }
}

pub struct FileWriter<'a> {
    env: Environment<'a, DownloadServerListConfig>,
    servers: DownloadResponses,
}

impl<'a> FileWriter<'a> {
    pub async fn write_servers_to_file(self) -> PartialResult<ExitStatus> {
        info!("Writing nameserver configs to file.");
        FileWriter::write_servers(&self.env.mod_config.output_file_path, &self.servers).await?;
        info!("Finished writing.");

        if self.env.console.not_quiet() {
            self.env
                .console
                .ok(format!("Saved to file '{}'.", &self.env.mod_config.output_file_path));
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
