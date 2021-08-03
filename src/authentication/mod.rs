pub mod password;
pub mod token;

use crate::{error, model::Status};

use warp::hyper::StatusCode;

#[derive(Debug, thiserror::Error)]
pub enum AuthenticationError {
    #[error("insufficient permission")]
    InsufficientPermission,
    #[error("header error: {0}")]
    InvalidHeader(String),
    #[error("password error: {0}")]
    Password(#[from] password::PasswordError),
    #[error("token error: {0}")]
    Token(#[from] token::TokenError),
}

impl warp::reject::Reject for AuthenticationError {}

impl error::ErrorResponse for AuthenticationError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        match self {
            AuthenticationError::InsufficientPermission => StatusCode::FORBIDDEN,
            AuthenticationError::InvalidHeader(_) => StatusCode::UNAUTHORIZED,
            AuthenticationError::Token(_) => StatusCode::UNAUTHORIZED,
            AuthenticationError::Password(_) => StatusCode::BAD_REQUEST,
        }
    }

    fn error_response(&self) -> Self::Response {
        Status::new(self.status_code(), self.to_string())
    }
}
