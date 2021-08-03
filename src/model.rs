use std::marker::Send;

use mongodb::bson::Document;
use serde::{Deserialize, Deserializer, Serialize};
use warp::{hyper::StatusCode, reply, Reply};

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

impl Reply for Status {
    fn into_response(self) -> warp::reply::Response {
        let status = StatusCode::from_u16(self.code).unwrap();
        reply::with_status(reply::json(&self), status).into_response()
    }
}

impl From<Status> for warp::reply::Response {
    fn from(val: Status) -> Self {
        val.into_response()
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct List<T: Serialize> {
    total: u64,
    data: Vec<T>,
}

impl<T: Serialize + Send> Reply for List<T> {
    fn into_response(self) -> reply::Response {
        reply::json(&self).into_response()
    }
}

impl<T: Serialize + Send> From<List<T>> for warp::reply::Response {
    fn from(val: List<T>) -> Self {
        val.into_response()
    }
}

impl<T: Serialize> List<T> {
    pub fn new(total: u64, data: Vec<T>) -> Self {
        Self { total, data }
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
