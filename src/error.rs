use crate::{
    action::ActionError,
    authentication::{
        password::PasswordError, token::TokenError as AuthTokenError, AuthenticationError,
    },
    client::ClientError,
    model::Status,
    service::ServiceError,
    session::SessionError,
    sso::SsoError,
    token::TokenError,
    user::UserError,
    utils::crypto::CryptoError,
};

use hyper::StatusCode;
use tower::BoxError;
use tracing::error;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("query error: {0}")]
    Query(#[from] QueryError),
    #[error("authentication token error: {0}")]
    AuthToken(#[from] AuthTokenError),
    #[error("authentication error: {0}")]
    Auth(#[from] AuthenticationError),
    #[error("user error: {0}")]
    User(#[from] UserError),
    #[error("client error: {0}")]
    Client(#[from] ClientError),
    #[error("service error: {0}")]
    Service(#[from] ServiceError),
    #[error("session error: {0}")]
    Session(#[from] SessionError),
    #[error("MongoDB error: {0}")]
    Action(#[from] ActionError),
    #[error("action error: {0}")]
    Token(#[from] TokenError),
    #[error("sso error: {0}")]
    Sso(#[from] SsoError),
    #[error("Http error: {0}")]
    Http(#[from] http::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("database error: {0}")]
    Database(#[from] mongodb::error::Error),
    #[error("Envy error: {0}")]
    Envy(#[from] envy::Error),
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("password error: {0}")]
    Password(#[from] PasswordError),
}

impl axum::response::IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        let res = match self {
            Error::Auth(e) => e.error_response(),
            Error::Query(e) => e.error_response(),
            Error::User(e) => e.error_response(),
            Error::Client(e) => e.error_response(),
            Error::Session(e) => e.error_response(),
            Error::Service(e) => e.error_response(),
            Error::Action(e) => e.error_response(),
            Error::Token(e) => e.error_response(),
            Error::Sso(e) => e.error_response(),
            Error::AuthToken(e) => e.error_response(),
            Error::Password(e) => AuthenticationError::from(e).error_response(),
            _ => {
                error!(error = %self, "internal error");
                Status::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
        };

        res.into_response()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("invalid data")]
    InvalidBody,
}

impl ErrorResponse for QueryError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        match self {
            QueryError::InvalidBody => StatusCode::BAD_REQUEST,
        }
    }

    fn error_response(&self) -> Self::Response {
        Status::new(self.status_code(), self.to_string())
    }
}

pub async fn handle_error(error: BoxError) -> Status {
    if error.is::<tower::timeout::error::Elapsed>() {
        return Status::new(StatusCode::REQUEST_TIMEOUT, "request timed out");
    }

    if error.is::<tower::load_shed::error::Overloaded>() {
        return Status::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "service is overloaded, try again later",
        );
    }

    error!(error = %error, "internal error");
    Status::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

pub trait ErrorResponse
where
    Self: std::error::Error,
{
    type Response: axum::response::IntoResponse;

    fn status_code(&self) -> axum::http::StatusCode;

    fn error_response(&self) -> Self::Response;
}
