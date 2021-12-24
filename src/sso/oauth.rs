use chrono::{serde::ts_seconds, DateTime, Utc};

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateClaims {
    pub aud: Vec<String>,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,
}

impl StateClaims {
    pub const DEFAULT_EXP_MIN: i64 = 60;

    pub(super) fn new<A>(aud: A) -> Self
    where
        A: IntoIterator<Item = String>,
    {
        Self {
            aud: aud.into_iter().collect(),
            exp: Utc::now() + chrono::Duration::minutes(Self::DEFAULT_EXP_MIN),
            iat: Utc::now(),
        }
    }
}
