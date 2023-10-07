mod handler;
pub mod model;
mod routes;

use crate::services::model::Status;

use super::error::ErrorResponse;

use hyper::StatusCode;

pub use routes::routes;

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("service not found")]
    NotFound,
    #[error("service id is invalid")]
    InvalidId,
    #[error("scope is not defined")]
    UndefinedScope,
    #[error("requirement is not met")]
    RequirementNotMet,
}

impl ErrorResponse for ServiceError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        match self {
            ServiceError::NotFound => StatusCode::NOT_FOUND,
            ServiceError::InvalidId | ServiceError::UndefinedScope => StatusCode::BAD_REQUEST,
            ServiceError::RequirementNotMet => StatusCode::FORBIDDEN,
        }
    }

    fn error_response(&self) -> Self::Response {
        Status::new(self.status_code(), self.to_string())
    }
}

impl axum::response::IntoResponse for ServiceError {
    fn into_response(self) -> axum::response::Response {
        self.error_response().into_response()
    }
}
