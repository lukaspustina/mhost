use std::ffi::OsString;

use anyhow::Result;
use tracing::subscriber::set_global_default;
use tracing_log::LogTracer;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::{self, format::FmtSpan};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::EnvFilter;

pub struct Logging {
    verbosity: u64,
    rust_log: Option<OsString>,
    color: bool,
    debug: bool,
}

impl Logging {
    pub fn new(verbosity: u64, rust_log: Option<OsString>, color: bool, debug: bool) -> Logging {
        Logging {
            verbosity,
            rust_log,
            color,
            debug,
        }
    }

    fn log_level(verbosity: u64) -> LevelFilter {
        match verbosity {
            0 => LevelFilter::WARN,
            1 => LevelFilter::INFO,
            2 => LevelFilter::DEBUG,
            _ => LevelFilter::TRACE,
        }
    }

    pub fn start(self) -> Result<()> {
        // Subscribe to all log crate log messages and transform them to a tracing events
        LogTracer::init()?;

        let log_level = Logging::log_level(self.verbosity);
        let filter = if self.rust_log.is_some() {
            // This is controlled by the env variable RUST_LOG and overrides the max level, if set
            EnvFilter::from_default_env()
        } else {
            // If RUST_LOG is not set, use `-` arg to determine log level
            EnvFilter::from(format!("{}={}", env!("CARGO_CRATE_NAME"), log_level))
        };

        let fmt = if self.debug {
            fmt::layer()
                .with_ansi(self.color)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_target(true)
                .with_span_events(FmtSpan::FULL)
        } else {
            fmt::layer()
                .with_ansi(self.color)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_target(false)
        };

        let registry = tracing_subscriber::registry().with(filter).with(fmt);
        set_global_default(registry)?;

        Ok(())
    }
}
