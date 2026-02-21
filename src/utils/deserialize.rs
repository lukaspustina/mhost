// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[cfg(feature = "services")]
use serde::{de, Deserialize, Deserializer};
#[cfg(feature = "services")]
use std::str::FromStr;

#[cfg(feature = "services")]
pub fn des_f32_from_string<'de, D>(deserializer: D) -> Result<f32, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let float = f32::from_str(&s).map_err(de::Error::custom)?;
    Ok(float)
}
