mod handler;
mod routes;

use crate::{error, model::Response};

use http::StatusCode;
use serde::Serialize;

pub use routes::routes;

/// Bytes length of client id.
pub const CLIENT_ID_LENGTH: usize = 16;

/// Bytes length of client secret.
pub const CLIENT_SECRET_LENGTH: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum OauthError {
    #[error("invalid request")]
    InvalidRequest,
    #[error("invalid client")]
    InvalidClient,
    #[error("invalid grant")]
    InvalidGrant,
    #[error("unauthorized client")]
    UnauthorizedClient,
    #[error("unsupported grant type")]
    UnsupportedGrantType,
    #[error("invalid scope")]
    InvalidScope,
    #[error("internal error")]
    InternalError,
}

impl error::ErrorResponse for OauthError {
    type Response = Response<ErrorResponse>;

    fn status_code(&self) -> StatusCode {
        match self {
            OauthError::InvalidRequest
            | OauthError::InvalidGrant
            | OauthError::UnsupportedGrantType
            | OauthError::InvalidScope => StatusCode::BAD_REQUEST,
            OauthError::InvalidClient | OauthError::UnauthorizedClient => StatusCode::UNAUTHORIZED,
            OauthError::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> Self::Response {
        let error = ErrorResponse {
            error: self.into(),
            error_description: None,
        };

        Response::with_status(self.status_code(), error)
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: ErrorType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

// Error responses defined in RFC 6749
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorType {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
    ServerError,
}

impl From<&OauthError> for ErrorType {
    fn from(error: &OauthError) -> Self {
        match error {
            OauthError::InvalidRequest => ErrorType::InvalidRequest,
            OauthError::InvalidClient => ErrorType::InvalidClient,
            OauthError::InvalidGrant => ErrorType::InvalidGrant,
            OauthError::UnauthorizedClient => ErrorType::UnauthorizedClient,
            OauthError::UnsupportedGrantType => ErrorType::UnsupportedGrantType,
            OauthError::InvalidScope => ErrorType::InvalidScope,
            OauthError::InternalError => ErrorType::ServerError,
        }
    }
}
