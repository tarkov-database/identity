use std::convert::Infallible;

use crate::{
    action::ActionError, authentication::AuthenticationError, client::ClientError, model::Status,
    service::ServiceError, session::SessionError, user::UserError,
};

use log::error;
use warp::{
    body::BodyDeserializeError,
    hyper::StatusCode,
    reject::{MethodNotAllowed, MissingHeader},
    Rejection, Reply,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("query error: {0}")]
    Query(#[from] QueryError),
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
    Database(#[from] mongodb::error::Error),
    #[error("Envy error: {0}")]
    Envy(#[from] envy::Error),
    #[error("reqwest error: {0}")]
    Http(#[from] reqwest::Error),
}

impl warp::reject::Reject for Error {}

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("invalid data")]
    InvalidBody,
}

impl warp::reject::Reject for QueryError {}

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

pub async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    if let Some(err) = err.find::<Error>() {
        let res = match err {
            Error::Auth(e) => e.error_response(),
            Error::Query(e) => e.error_response(),
            Error::User(e) => e.error_response(),
            Error::Client(e) => e.error_response(),
            Error::Session(e) => e.error_response(),
            Error::Service(e) => e.error_response(),
            Error::Action(e) => e.error_response(),
            Error::Database(e) => {
                error!("database error: {:?}", e);
                Status::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            Error::Http(e) => {
                error!("http client error: {:?}", e);
                Status::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            }
            Error::Envy(_) => unreachable!(),
        };
        return Ok(res);
    }

    if err.is_not_found() {
        return Ok(Status::new(StatusCode::NOT_FOUND, "resource not found"));
    }

    if let Some(e) = err.find::<MissingHeader>() {
        let (code, msg) = match e.name() {
            "authorization" => (StatusCode::UNAUTHORIZED, String::from("not authorized")),
            _ => (
                StatusCode::BAD_REQUEST,
                format!("\"{}\" header is missing", e.name()),
            ),
        };
        return Ok(Status::new(code, msg));
    }

    if let Some(err) = err.find::<BodyDeserializeError>() {
        return Ok(Status::new(StatusCode::BAD_REQUEST, err));
    }

    if let Some(e) = err.find::<MethodNotAllowed>() {
        return Ok(Status::new(StatusCode::METHOD_NOT_ALLOWED, e));
    }

    error!("unhandled rejection: {:?}", err);
    Ok(Status::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal error",
    ))
}

pub trait ErrorResponse
where
    Self: std::error::Error + warp::reject::Reject,
{
    type Response: Reply;

    fn status_code(&self) -> warp::hyper::StatusCode;

    fn error_response(&self) -> Self::Response;
}
