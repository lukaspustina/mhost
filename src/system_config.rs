use std::fs::File;
use std::io::Read;

use resolv_conf::Config;

use crate::{Error, Result};
use std::path::Path;

pub fn load_from_system_config<T: From<Config>>() -> Result<T> {
    load_from_system_config_path("/etc/resolv.conf")
}

pub fn load_from_system_config_path<T: From<Config>, P: AsRef<Path>>(path: P) -> Result<T> {
    let path = path.as_ref();
    let mut buf = Vec::with_capacity(4096);
    let mut f = File::open(path)?;
    f.read_to_end(&mut buf)?;
    let cfg = resolv_conf::Config::parse(&buf).map_err(|e| Error::ParserError {
        what: format!("{}", path.to_string_lossy()),
        to: "",
        why: e.to_string(),
    })?;

    Ok(cfg.into())
}
