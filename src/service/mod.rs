mod handler;
pub mod model;
mod routes;

use crate::{error, model::Status};

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
}

impl error::ErrorResponse for ServiceError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        match self {
            ServiceError::NotFound => StatusCode::NOT_FOUND,
            ServiceError::InvalidId | ServiceError::UndefinedScope => StatusCode::BAD_REQUEST,
        }
    }

    fn error_response(&self) -> Self::Response {
        Status::new(self.status_code(), self.to_string())
    }
}
