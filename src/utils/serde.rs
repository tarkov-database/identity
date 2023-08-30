use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Deserializer};

/// Deserialize a comma-separated borrowed string into a vector of T.
pub fn deserialize_vec_from_str<'de, T, D>(d: D) -> Result<Vec<T>, D::Error>
where
    T: FromStr,
    T::Err: Display,
    D: Deserializer<'de>,
{
    let s = <&str>::deserialize(d)?;
    let v = s
        .split(',')
        .map(|s| s.trim().parse::<T>())
        .collect::<Result<Vec<T>, _>>()
        .map_err(|e| serde::de::Error::custom(e.to_string()))?;

    Ok(v)
}

/// Deserialize a comma-separated string into a vector of T.
pub fn deserialize_vec_from_string<'de, T, D>(d: D) -> Result<Vec<T>, D::Error>
where
    T: FromStr,
    T::Err: Display,
    D: Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    let v = s
        .split(',')
        .map(|s| s.trim().parse::<T>())
        .collect::<Result<Vec<T>, _>>()
        .map_err(|e| serde::de::Error::custom(e.to_string()))?;

    Ok(v)
}
