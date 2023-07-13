mod handler;
pub mod model;
mod routes;

use crate::{
    auth::token::{Token, TokenType, TokenValidation, LEEWAY},
    error,
    model::Status,
};

use chrono::{serde::ts_seconds, DateTime, Utc};
use http::StatusCode;
use serde::{Deserialize, Serialize};

pub use routes::routes;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("client not found")]
    NotFound,
    #[error("client id is invalid")]
    InvalidId,
    #[error("client is locked")]
    Locked,
    #[error("token expiration is invalid")]
    InvalidExpiration,
}

impl error::ErrorResponse for ClientError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        match self {
            ClientError::NotFound => StatusCode::NOT_FOUND,
            ClientError::InvalidId | ClientError::InvalidExpiration => StatusCode::BAD_REQUEST,
            ClientError::Locked => StatusCode::FORBIDDEN,
        }
    }

    fn error_response(&self) -> Self::Response {
        Status::new(self.status_code(), self.to_string())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientClaims {
    pub jti: Uuid,
    pub aud: String,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub nbf: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,
    pub sub: String,
    pub iss: String,
}

impl ClientClaims {
    const AUDIENCE_CLIENT: &str = "identity/client";

    fn new(id: impl Into<Uuid>, sub: &str, iss: &str, exp: DateTime<Utc>) -> Self {
        Self {
            jti: id.into(),
            aud: Self::AUDIENCE_CLIENT.to_string(),
            exp,
            nbf: Utc::now(),
            iat: Utc::now(),
            sub: sub.into(),
            iss: iss.into(),
        }
    }
}

impl Token for ClientClaims {
    const TYPE: TokenType = TokenType::Refresh;

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

impl TokenValidation for ClientClaims {
    fn validation(alg: jsonwebtoken::Algorithm) -> jsonwebtoken::Validation {
        let mut validation = jsonwebtoken::Validation::new(alg);
        validation.leeway = LEEWAY;
        validation.set_required_spec_claims(&["jti", "exp", "nbf", "sub", "aud", "iat"]);
        validation.set_audience(&[Self::AUDIENCE_CLIENT]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation
    }
}
