mod handler;
mod routes;

use crate::{
    auth::token::{Token, TokenType, TokenValidation, LEEWAY},
    services::model::Status,
};

use super::error::ErrorResponse;

use chrono::{serde::ts_seconds, DateTime, Duration, Utc};
use hyper::StatusCode;
use mongodb::bson::{oid::ObjectId, serde_helpers::serialize_object_id_as_hex_string};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use handler::SessionResponse;
pub use routes::routes;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("invalid session")]
    InvalidSession,
    #[error("credentials are wrong")]
    BadCredentials,
    #[error("not authorized: {0}")]
    NotAuthorized(String),
    #[error("login is required")]
    LoginRequired,
}

impl ErrorResponse for SessionError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        match self {
            SessionError::BadCredentials
            | SessionError::LoginRequired
            | SessionError::InvalidSession => StatusCode::UNAUTHORIZED,
            SessionError::NotAuthorized(_) => StatusCode::FORBIDDEN,
        }
    }

    fn error_response(&self) -> Self::Response {
        Status::new(self.status_code(), self.to_string())
    }
}

impl axum::response::IntoResponse for SessionError {
    fn into_response(self) -> axum::response::Response {
        self.error_response().into_response()
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionClaims {
    pub jti: Uuid,
    pub aud: String,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub nbf: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,
    #[serde(serialize_with = "serialize_object_id_as_hex_string")]
    pub sub: ObjectId,
}

impl SessionClaims {
    const AUDIENCE_SESSION: &str = "identity/session";

    pub const DEFAULT_EXP_MIN: i64 = 60 * 24 * 7;

    pub fn new(id: impl Into<Uuid>, user_id: ObjectId) -> Self {
        Self {
            jti: id.into(),
            aud: Self::AUDIENCE_SESSION.into(),
            exp: Utc::now() + Duration::minutes(Self::DEFAULT_EXP_MIN),
            nbf: Utc::now(),
            iat: Utc::now(),
            sub: user_id,
        }
    }

    pub fn set_expiration(&mut self, date: DateTime<Utc>) {
        self.exp = date;
    }
}

impl Token for SessionClaims {
    const TYPE: TokenType = TokenType::Session;

    fn expires_at(&self) -> DateTime<Utc> {
        self.exp
    }

    fn not_before(&self) -> DateTime<Utc> {
        self.nbf
    }

    fn issued_at(&self) -> DateTime<Utc> {
        self.iat
    }
}

impl TokenValidation for SessionClaims {
    fn validation(alg: jsonwebtoken::Algorithm) -> jsonwebtoken::Validation {
        let mut validation = jsonwebtoken::Validation::new(alg);
        validation.leeway = LEEWAY;
        validation.set_required_spec_claims(&["jti", "exp", "nbf", "sub", "aud", "iat"]);
        validation.set_audience(&[Self::AUDIENCE_SESSION]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation
    }
}
