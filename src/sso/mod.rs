mod github;
mod oauth;
mod routes;

use crate::{error, model::Status};

use self::github::GitHubError;

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
    GitHub(#[from] GitHubError),
}

impl error::ErrorResponse for SsoError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        match self {
            SsoError::StateMissing => StatusCode::BAD_REQUEST,
            SsoError::InvalidState => StatusCode::UNAUTHORIZED,
            SsoError::EmailInvalid => StatusCode::UNPROCESSABLE_ENTITY,
            SsoError::GitHub(e) => e.status_code(),
        }
    }

    fn error_response(&self) -> Self::Response {
        Status::new(self.status_code(), self.to_string())
    }
}
