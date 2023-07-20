mod handler;
pub mod model;
mod routes;

use crate::services::model::Status;

use http::StatusCode;

pub use routes::routes;

use super::error::ErrorResponse;

/// The maximum validity of client credentials in seconds.
pub(super) const CREDENTIALS_MAX_VALIDITY: u64 = 60 * 60 * 24 * 365;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("client not found")]
    NotFound,
    #[error("client id is invalid")]
    InvalidId,
    #[error("client already exists")]
    Locked,
    #[error("token expiration is invalid")]
    InvalidValidity,
}

impl ErrorResponse for ClientError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        match self {
            ClientError::NotFound => StatusCode::NOT_FOUND,
            ClientError::InvalidId | ClientError::InvalidValidity => StatusCode::BAD_REQUEST,
            ClientError::Locked => StatusCode::FORBIDDEN,
        }
    }

    fn error_response(&self) -> Self::Response {
        Status::new(self.status_code(), self.to_string())
    }
}

impl axum::response::IntoResponse for ClientError {
    fn into_response(self) -> axum::response::Response {
        self.error_response().into_response()
    }
}
