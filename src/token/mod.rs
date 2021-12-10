mod handler;
mod routes;

use crate::{
    authentication::token::{TokenClaims, TokenType},
    error,
    model::Status,
};

use chrono::{serde::ts_seconds, DateTime, Duration, Utc};
use hyper::StatusCode;
use serde::{Deserialize, Serialize};

pub use routes::routes;

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("token encoding failed")]
    Encoding,
}

impl error::ErrorResponse for TokenError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }

    fn error_response(&self) -> Self::Response {
        Status::new(self.status_code(), self.to_string())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientClaims {
    pub aud: Vec<String>,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,
    pub sub: String,
    pub iss: String,
    token_type: TokenType,
}

impl ClientClaims {
    pub const TOKEN_TYPE: TokenType = TokenType::Client;

    pub const DEFAULT_EXP_DAYS: i64 = 365;

    fn new<A>(aud: A, sub: &str, iss: &str) -> Self
    where
        A: IntoIterator<Item = String>,
    {
        Self {
            aud: aud.into_iter().collect(),
            exp: Utc::now() + Duration::days(Self::DEFAULT_EXP_DAYS),
            iat: Utc::now(),
            sub: sub.into(),
            iss: iss.into(),
            token_type: Self::TOKEN_TYPE,
        }
    }
}

impl TokenClaims for ClientClaims {
    const TOKEN_TYPE: TokenType = TokenType::Client;

    fn get_type(&self) -> &TokenType {
        &self.token_type
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceClaims {
    pub aud: Vec<String>,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,
    pub sub: String,
    #[serde(default)]
    pub scope: Vec<String>,
}

impl ServiceClaims {
    pub const DEFAULT_EXP_MIN: i64 = 30;

    fn new<A>(aud: A, sub: &str) -> Self
    where
        A: IntoIterator<Item = String>,
    {
        Self {
            aud: aud.into_iter().collect(),
            exp: Utc::now() + Duration::minutes(Self::DEFAULT_EXP_MIN),
            iat: Utc::now(),
            sub: sub.into(),
            scope: Vec::default(),
        }
    }

    fn with_scope<A, S>(aud: A, sub: &str, scope: S) -> Self
    where
        A: IntoIterator<Item = String>,
        S: IntoIterator<Item = String>,
    {
        let mut claims = Self::new(aud, sub);
        claims.scope = scope.into_iter().collect();

        claims
    }
}
