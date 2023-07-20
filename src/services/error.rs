use super::{
    action::ActionError, client::ClientError, model::Status, oauth::OauthError,
    service::ServiceError, session::SessionError, sso::SsoError, user::UserError,
};

use axum::http::header::{HeaderName, HeaderValue};
use http::StatusCode;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Action error
    #[error("action error: {0}")]
    Action(#[from] ActionError),

    /// Client error
    #[error("client error: {0}")]
    Client(#[from] ClientError),

    /// OAuth error
    #[error("oauth error: {0}")]
    Oauth(#[from] OauthError),

    /// Service error
    #[error("service error: {0}")]
    Service(#[from] ServiceError),

    /// Session error
    #[error("session error: {0}")]
    Session(#[from] SessionError),

    /// Single sign-on error
    #[error("sso error: {0}")]
    Sso(#[from] SsoError),

    /// User error
    #[error("user error: {0}")]
    User(#[from] UserError),

    /// Query error
    #[error("query error: {0}")]
    Query(#[from] QueryError),

    /// Auth error
    #[error("auth error: {0}")]
    Auth(#[from] crate::auth::AuthError),

    /// Password error
    #[error("password error: {0}")]
    Password(#[from] crate::auth::password::PasswordError),

    /// Token error
    #[error("token error: {0}")]
    Token(#[from] crate::auth::token::TokenError),

    /// Application error
    #[error("application error: {0}")]
    Application(#[from] crate::error::Error),
}

impl axum::response::IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        match self {
            Error::Action(e) => e.into_response(),
            Error::Client(e) => e.into_response(),
            Error::Oauth(e) => e.into_response(),
            Error::Service(e) => e.into_response(),
            Error::Session(e) => e.into_response(),
            Error::Sso(e) => e.into_response(),
            Error::User(e) => e.into_response(),
            Error::Query(e) => e.into_response(),
            Error::Auth(e) => e.into_response(),
            Error::Password(e) => e.into_response(),
            Error::Token(e) => e.into_response(),
            Error::Application(e) => {
                tracing::error!(error = %e, "internal server error");
                Status::new(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
                    .into_response()
            }
        }
    }
}

pub trait ErrorResponse
where
    Self: std::error::Error,
{
    type Response: axum::response::IntoResponse;

    fn status_code(&self) -> axum::http::StatusCode;

    fn header<I, K, V>(&self) -> Option<I>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<HeaderName>,
        V: Into<HeaderValue>,
    {
        None
    }

    fn error_response(&self) -> Self::Response;
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

impl axum::response::IntoResponse for QueryError {
    fn into_response(self) -> axum::response::Response {
        self.error_response().into_response()
    }
}

pub async fn handle_error(error: axum::BoxError) -> Status {
    if error.is::<tower::timeout::error::Elapsed>() {
        return Status::new(StatusCode::REQUEST_TIMEOUT, "request timed out");
    }

    if error.is::<tower::load_shed::error::Overloaded>() {
        return Status::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "service is overloaded, try again later",
        );
    }

    tracing::error!(error = %error, "internal error");
    Status::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}
