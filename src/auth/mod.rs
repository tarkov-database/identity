pub mod password;
pub mod token;

use crate::{error, services::error::ErrorResponse, services::model::Status};

use hyper::StatusCode;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("insufficient permission")]
    InsufficientPermission,

    #[error("header error: {0}")]
    InvalidHeader(String),
}

impl ErrorResponse for AuthError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        match self {
            AuthError::InsufficientPermission => StatusCode::FORBIDDEN,
            AuthError::InvalidHeader(_) => StatusCode::UNAUTHORIZED,
        }
    }

    fn error_response(&self) -> Self::Response {
        Status::new(self.status_code(), self.to_string())
    }
}

impl axum::response::IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        self.error_response().into_response()
    }
}
