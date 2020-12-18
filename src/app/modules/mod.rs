use thiserror::Error;

use crate::app::console::Console;
use crate::app::{self, AppConfig, ExitStatus};

pub mod check;
pub mod discover;
pub mod get_server_lists;
pub mod lookup;
pub mod soa_check;

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

/** Pass environment like configs and console access from step to step
 */
pub struct Environment<'a, T> {
    pub app_config: &'a AppConfig,
    pub mod_config: &'a T,
    pub console: Console,
}

impl<'a, T> Environment<'a, T> {
    pub fn new(app_config: &'a AppConfig, mod_config: &'a T, console: Console) -> Environment<'a, T> {
        Environment {
            app_config,
            mod_config,
            console,
        }
    }
}
