use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::app::console::{Console, ConsoleOpts};
use crate::app::resolver::{NameBuilder, NameBuilderOpts};
use crate::app::{self, AppConfig, ExitStatus};

pub mod check;
pub mod discover;
pub mod get_server_lists;
pub mod lookup;

/** Return type for App modules that go through multiple steps
 *
 * An App module might go through multiple distinct steps to eventually fulfill its task. Along this
 * way, errors might occur. Errors should be reported using `Result`. But what if a step finishes
 * without errors but still couldn't obtain the necessary information for the next step to proceed?
 * For this use case, `PartialResult` works similar to an Either type for the `Result::Err` side of the
 * execution.
 *
 * Think of it as a means for early returns.
 */
pub type PartialResult<T> = std::result::Result<T, PartialError>;

pub trait PartialResultExt {
    fn into_result(self) -> anyhow::Result<ExitStatus>;
}

impl PartialResultExt for PartialResult<ExitStatus> {
    fn into_result(self) -> anyhow::Result<ExitStatus> {
        match self {
            Ok(exit_status) => Ok(exit_status),
            Err(PartialError::Failed(exit_status)) => Ok(exit_status),
            Err(err @ PartialError::Err { .. }) => Err(err.into()),
        }
    }
}

#[derive(Debug, Error)]
pub enum PartialError {
    #[error("module step failed")]
    Failed(app::ExitStatus),
    #[error(transparent)]
    Err(#[from] anyhow::Error),
}

impl From<crate::error::Error> for PartialError {
    fn from(err: crate::error::Error) -> Self {
        PartialError::Err(anyhow::Error::new(err))
    }
}

impl From<crate::resolver::error::Error> for PartialError {
    fn from(err: crate::resolver::error::Error) -> Self {
        PartialError::Err(anyhow::Error::new(err))
    }
}

impl From<crate::services::error::Error> for PartialError {
    fn from(err: crate::services::error::Error) -> Self {
        PartialError::Err(anyhow::Error::new(err))
    }
}

/// Information about the current execution of `mhost`
#[derive(Debug, Serialize, Deserialize)]
pub struct RunInfo {
    pub start_time: DateTime<Utc>,
    pub command_line: String,
    pub version: &'static str,
}

impl RunInfo {
    pub fn now() -> Self {
        // skip args[0] as it contains the bin name
        let args: Vec<_> = std::env::args().skip(1).collect();
        let command_line = args.join(" ");
        RunInfo {
            start_time: Utc::now(),
            command_line,
            version: env!("CARGO_PKG_VERSION"),
        }
    }
}

/// Pass environment like configs and console access from step to step
pub struct Environment<'a, T> {
    pub run_info: RunInfo,
    pub app_config: &'a AppConfig,
    pub mod_config: &'a T,
    pub console: Console,
    pub name_builder: NameBuilder,
}

impl<'a, T> Environment<'a, T> {
    pub fn new(
        app_config: &'a AppConfig,
        mod_config: &'a T,
        console: Console,
        name_builder: NameBuilder,
    ) -> Environment<'a, T> {
        Environment {
            run_info: RunInfo::now(),
            app_config,
            mod_config,
            console,
            name_builder,
        }
    }
}

/// Base implementation for App modules
pub trait AppModule<T: ModConfig> {
    fn init_env<'a>(app_config: &'a AppConfig, config: &'a T) -> Result<Environment<'a, T>> {
        let console_opts = ConsoleOpts::from(app_config).with_partial_results(config.partial_results());
        let console = Console::new(console_opts);

        let name_builder_ops = if let Some(ref search_domain) = app_config.search_domain {
            NameBuilderOpts::new(app_config.ndots, search_domain.as_ref())
        } else {
            NameBuilderOpts::from_hostname(app_config.ndots)
        }?;
        let name_builder = NameBuilder::new(name_builder_ops);

        let env = Environment::new(app_config, config, console, name_builder);

        Ok(env)
    }
}

/// Base implementation for module configuration
pub trait ModConfig {
    fn partial_results(&self) -> bool {
        false
    }
}
