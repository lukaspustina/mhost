pub mod logging {
    use lazy_static;
    use tracing::subscriber::set_global_default;
    use tracing_log::LogTracer;
    use tracing_subscriber::fmt;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::EnvFilter;

    lazy_static::lazy_static! {
        static ref LOGGING: () = {
            // Subscribe to all log crate log messages and transform them to a tracing events
            LogTracer::init()
                .expect("failed to init logging for testing");

            let filter = if let Some(_) = std::env::var_os("RUST_LOG") {
                // This is controlled by the env variable RUST_LOG
                EnvFilter::from_default_env()
            } else {
                // If RUST_LOG is not set
                EnvFilter::from(format!("{}=info", env!("CARGO_CRATE_NAME")))
            };

            let fmt = fmt::layer()
                .with_test_writer()
                .with_ansi(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_target(false);

            let registry = tracing_subscriber::registry().with(filter).with(fmt);
            set_global_default(registry)
                .expect("failed to init tracing for testing");
        };
    }

    pub fn init() {
        lazy_static::initialize(&LOGGING);
    }
}
