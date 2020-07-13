use resolv_conf::Config;
use std::fs::File;
use std::io::Read;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SystemConfigError {
    #[error("failed to read")]
    IoError {
        #[from]
        source: std::io::Error,
    },
    #[error("failed to parse")]
    ParserError {
        #[from]
        source: resolv_conf::ParseError,
    },
}

pub fn load_from_system_config<T: From<Config>>() -> std::result::Result<T, SystemConfigError> {
    let mut buf = Vec::with_capacity(4096);
    let mut f = File::open("/etc/resolv.conf")?;
    f.read_to_end(&mut buf)?;
    let cfg = resolv_conf::Config::parse(&buf)?;

    Ok(cfg.into())
}
