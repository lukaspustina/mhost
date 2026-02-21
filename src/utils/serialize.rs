// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::nameserver::NameServerConfig;

use serde::{Deserialize, Serializer};
use std::sync::Arc;

pub fn ser_arc_nameserver_config<S>(data: &Arc<NameServerConfig>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&data.to_string())
}

pub fn deser_arc_nameserver_config<'de, D>(deserializer: D) -> Result<Arc<NameServerConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let config = NameServerConfig::from_str(&s).map_err(serde::de::Error::custom)?;
    Ok(Arc::new(config))
}

#[cfg(feature = "services")]
pub fn ser_to_string<S, T: ToString>(data: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&data.to_string())
}
