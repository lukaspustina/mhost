use serde::{Deserializer, de, Deserialize};
use std::str::FromStr;

pub fn des_f32_from_string<'de, D>(deserializer: D) -> Result<f32, D::Error>
where
    D: Deserializer<'de>
{
    let s = String::deserialize(deserializer)?;
    let float = f32::from_str(&s)
        .map_err(de::Error::custom)?;
    Ok(float)
}
