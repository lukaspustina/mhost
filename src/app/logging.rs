use log::LevelFilter;
use std::io::Write;

pub fn start_logging_for_level(verbosity: u64) {
    let log_level = log_level(verbosity);
    setup_logging(log_level)
}

fn log_level(verbosity: u64) -> LevelFilter {
    match verbosity {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    }
}

fn setup_logging(log_level: LevelFilter) {
    let start = std::time::Instant::now();
    env_logger::Builder::from_default_env()
        .filter_module("mhost", log_level)
        .format(move |buf, rec| {
            let t = start.elapsed().as_secs_f32();
            let thread_id_string = format!("{:?}", std::thread::current().id());
            let thread_id = &thread_id_string[9..thread_id_string.len() - 1];
            writeln!(buf, "{:.03} [{:5}] ({:}) - {}", t, rec.level(), thread_id, rec.args())
        })
        .init();
}
