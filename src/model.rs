use hyper::StatusCode;
use mongodb::bson::Document;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub code: u16,
    pub message: String,
}

impl Status {
    pub fn new<S>(code: StatusCode, message: S) -> Self
    where
        S: ToString,
    {
        Self {
            code: code.as_u16(),
            message: message.to_string(),
        }
    }
}

impl axum::response::IntoResponse for Status {
    fn into_response(self) -> axum::response::Response {
        let mut res = axum::Json(&self).into_response();
        *res.status_mut() = StatusCode::from_u16(self.code).unwrap();

        res
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct List<T: Serialize> {
    total: u64,
    data: Vec<T>,
}

impl<T: Serialize> List<T> {
    pub fn new<D>(total: u64, data: D) -> Self
    where
        D: IntoIterator,
        D::Item: Into<T>,
    {
        Self {
            total,
            data: data.into_iter().map(|d| d.into()).collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListOptions {
    #[serde(default = "default_limit", deserialize_with = "de_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: u64,
    pub sort: Option<Document>,
}

impl ListOptions {
    const MAX_LIMIT: i64 = 100;

    // pub fn new(limit: i64, offset: u64, sort: Option<Document>) -> Self {
    //     let limit = if limit > Self::MAX_LIMIT { 100 } else { limit };

    //     Self {
    //         limit,
    //         offset,
    //         sort,
    //     }
    // }
}

impl Default for ListOptions {
    fn default() -> Self {
        Self {
            limit: default_limit(),
            offset: 0,
            sort: None,
        }
    }
}

const fn default_limit() -> i64 {
    20
}

fn de_limit<'de, D>(d: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    let input = i64::deserialize(d)?;
    let output = if input > ListOptions::MAX_LIMIT {
        100
    } else {
        input
    };

    Ok(output)
}
