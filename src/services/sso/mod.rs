mod github;
mod oauth;
mod routes;

use crate::services::model::Status;

use super::error::ErrorResponse;

use http::StatusCode;

pub use github::GitHub;
pub use routes::routes;

#[derive(Debug, thiserror::Error)]
pub enum SsoError {
    #[error("no state was sent")]
    StateMissing,
    #[error("wrong state value")]
    InvalidState,
    #[error("email address doesn't meet the requirements")]
    EmailInvalid,
    #[error("GitHub returned an error: {0}")]
    GitHub(#[from] github::TokenAccessError),
    #[error("http client error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("unknown error")]
    UnknownError,
}

impl ErrorResponse for SsoError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        match self {
            SsoError::StateMissing => StatusCode::BAD_REQUEST,
            SsoError::InvalidState => StatusCode::UNAUTHORIZED,
            SsoError::EmailInvalid => StatusCode::UNPROCESSABLE_ENTITY,
            SsoError::GitHub(e) => e.status_code(),
            SsoError::Reqwest(_) => StatusCode::BAD_GATEWAY,
            SsoError::UnknownError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> Self::Response {
        Status::new(self.status_code(), self.to_string())
    }
}

impl axum::response::IntoResponse for SsoError {
    fn into_response(self) -> axum::response::Response {
        self.error_response().into_response()
    }
}
