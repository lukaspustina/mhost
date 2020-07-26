use std::fs::File;
use std::io::Read;

use resolv_conf::Config;

use crate::{Error, Result};

pub fn load_from_system_config<T: From<Config>>() -> Result<T> {
    let mut buf = Vec::with_capacity(4096);
    let mut f = File::open("/etc/resolv.conf")?;
    f.read_to_end(&mut buf)?;
    let cfg = resolv_conf::Config::parse(&buf).map_err(|e| Error::ParserError {
        what: "resolv.conf".to_string(),
        to: "",
        why: e.to_string(),
    })?;

    Ok(cfg.into())
}
