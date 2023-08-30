use crate::utils;

use std::str::FromStr;

use axum::http::header::{HeaderName, HeaderValue};
use hyper::StatusCode;
use mongodb::{bson::Bson, options::FindOptions};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug)]
pub struct Response<T>
where
    T: serde::Serialize,
{
    status: StatusCode,
    header: Option<axum::headers::HeaderMap>,
    body: T,
}

impl<T> Response<T>
where
    T: serde::Serialize,
{
    const DEFAULT_STATUS: StatusCode = StatusCode::OK;

    pub fn new(body: T) -> Self {
        Self {
            status: Self::DEFAULT_STATUS,
            header: None,
            body,
        }
    }

    pub fn with_status(status: impl Into<StatusCode>, body: T) -> Self {
        Self {
            status: status.into(),
            header: None,
            body,
        }
    }

    pub fn append_header<I, K, V>(&mut self, header: I)
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<HeaderName>,
        V: Into<HeaderValue>,
    {
        if let Some(h) = &mut self.header {
            h.extend(header.into_iter().map(|(k, v)| (k.into(), v.into())));
        } else {
            self.header = Some(
                header
                    .into_iter()
                    .map(|(k, v)| (k.into(), v.into()))
                    .collect(),
            );
        }
    }
}

impl<T> axum::response::IntoResponse for Response<T>
where
    T: serde::Serialize,
{
    fn into_response(self) -> axum::response::Response {
        let mut res = axum::Json(&self.body).into_response();
        *res.status_mut() = self.status;
        if let Some(h) = self.header {
            res.headers_mut().extend(h.into_iter())
        }

        res
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    #[serde(serialize_with = "se_status_code_as_u16")]
    pub code: StatusCode,
    pub message: String,
}

impl Status {
    pub fn new<S>(code: StatusCode, message: S) -> Self
    where
        S: ToString,
    {
        Self {
            code,
            message: message.to_string(),
        }
    }
}

impl axum::response::IntoResponse for Status {
    fn into_response(self) -> axum::response::Response {
        let mut res = axum::Json(&self).into_response();
        *res.status_mut() = self.code;

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

#[derive(Debug, Clone)]
pub enum SortOrder {
    Ascending,
    Descending,
}

#[derive(Debug, Clone)]
pub struct Sort {
    pub field: String,
    pub order: SortOrder,
}

impl FromStr for Sort {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sort = match s.strip_prefix('-') {
            Some(v) if !v.is_empty() => Self {
                field: v.to_string(),
                order: SortOrder::Descending,
            },
            _ => {
                if s.is_empty() {
                    return Err(());
                }

                Self {
                    field: s.to_string(),
                    order: SortOrder::Ascending,
                }
            }
        };

        Ok(sort)
    }
}

impl<'de> Deserialize<'de> for Sort {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        Self::from_str(&s).map_err(|_| serde::de::Error::custom("invalid sort"))
    }
}

impl From<Sort> for mongodb::bson::Document {
    fn from(sort: Sort) -> Self {
        let order = match sort.order {
            SortOrder::Ascending => 1,
            SortOrder::Descending => -1,
        };

        mongodb::bson::doc! { sort.field: order }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListOptions {
    #[serde(default = "default_limit", deserialize_with = "de_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: u64,
    pub sort: Option<Sort>,
}

impl From<ListOptions> for FindOptions {
    fn from(opts: ListOptions) -> Self {
        FindOptions::builder()
            .batch_size(opts.limit as u32)
            .skip(opts.offset)
            .limit(opts.limit)
            .sort(opts.sort.map(Into::into))
            .build()
    }
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

fn se_status_code_as_u16<S>(x: &StatusCode, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_u16(x.as_u16())
}

#[derive(Debug)]
pub struct InvalidEmailAddr;

impl std::fmt::Display for InvalidEmailAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid email address")
    }
}

impl std::error::Error for InvalidEmailAddr {}

#[derive(Debug, Clone)]
pub struct EmailAddr(String);

impl EmailAddr {
    pub fn new(addr: impl Into<String>) -> Result<Self, InvalidEmailAddr> {
        addr.into().try_into()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn local(&self) -> &str {
        self.0.split('@').next().unwrap()
    }

    pub fn domain(&self) -> &str {
        self.0.split('@').last().unwrap()
    }
}

impl TryFrom<String> for EmailAddr {
    type Error = InvalidEmailAddr;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if !utils::validation::is_valid_email(&value) {
            return Err(InvalidEmailAddr);
        }

        Ok(Self(value))
    }
}

impl std::fmt::Display for EmailAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<str> for EmailAddr {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq for EmailAddr {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl Serialize for EmailAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for EmailAddr {
    fn deserialize<D>(deserializer: D) -> Result<EmailAddr, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.try_into().map_err(serde::de::Error::custom)
    }
}

impl From<EmailAddr> for Bson {
    fn from(v: EmailAddr) -> Self {
        Bson::String(v.0)
    }
}
