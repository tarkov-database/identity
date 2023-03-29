pub mod password;
pub mod token;

use crate::{error, model::Status};

use hyper::StatusCode;

#[derive(Debug, thiserror::Error)]
pub enum AuthenticationError {
    #[error("insufficient permission")]
    InsufficientPermission,
    #[error("header error: {0}")]
    InvalidHeader(String),
}

impl error::ErrorResponse for AuthenticationError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        match self {
            AuthenticationError::InsufficientPermission => StatusCode::FORBIDDEN,
            AuthenticationError::InvalidHeader(_) => StatusCode::UNAUTHORIZED,
        }
    }

    fn error_response(&self) -> Self::Response {
        Status::new(self.status_code(), self.to_string())
    }
}
