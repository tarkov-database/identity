mod handler;
pub mod model;
mod routes;

use crate::{error, services::model::Status};

use super::error::ErrorResponse;

use hyper::StatusCode;

pub use routes::routes;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum UserError {
    #[error("user not found")]
    NotFound,
    #[error("user already exists")]
    AlreadyExists,
    #[error("user id is invalid")]
    InvalidId,
    #[error("email address invalid")]
    InvalidAddr,
    #[error("email address not allowed")]
    DomainNotAllowed,
    #[error("user is not verified")]
    NotVerified,
    #[error("user is locked")]
    Locked,
    #[error("user is not allowed to login")]
    LoginNotAllowed,
}

impl ErrorResponse for UserError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        match self {
            UserError::NotFound => StatusCode::NOT_FOUND,
            UserError::AlreadyExists | UserError::InvalidAddr | UserError::InvalidId => {
                StatusCode::BAD_REQUEST
            }
            UserError::NotVerified | UserError::Locked | UserError::LoginNotAllowed => {
                StatusCode::FORBIDDEN
            }
            UserError::DomainNotAllowed => StatusCode::UNPROCESSABLE_ENTITY,
        }
    }

    fn error_response(&self) -> Self::Response {
        Status::new(self.status_code(), self.to_string())
    }
}

impl axum::response::IntoResponse for UserError {
    fn into_response(self) -> axum::response::Response {
        self.error_response().into_response()
    }
}
