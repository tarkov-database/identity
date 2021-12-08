mod handler;
mod routes;

use crate::{
    authentication::{
        token::{TokenConfig, TokenError as AuthTokenError},
        AuthenticationError,
    },
    error::{self, Error},
    model::Status,
};

use axum::{
    async_trait,
    extract::{Extension, FromRequest, RequestParts, TypedHeader},
};
use chrono::{serde::ts_seconds, DateTime, Duration, Utc};
use headers::{authorization::Bearer, Authorization};
use hyper::StatusCode;
use serde::{Deserialize, Serialize};

pub use routes::routes;

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("token encoding failed")]
    Encoding,
}

impl error::ErrorResponse for TokenError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }

    fn error_response(&self) -> Self::Response {
        Status::new(self.status_code(), self.to_string())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientClaims {
    pub aud: Vec<String>,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,
    pub sub: String,
    pub iss: String,
}

impl ClientClaims {
    pub const DEFAULT_EXP_DAYS: i64 = 365;

    fn new<A>(aud: A, sub: &str, iss: &str) -> Self
    where
        A: IntoIterator<Item = String>,
    {
        Self {
            aud: aud.into_iter().collect(),
            exp: Utc::now() + Duration::days(Self::DEFAULT_EXP_DAYS),
            iat: Utc::now(),
            sub: sub.into(),
            iss: iss.into(),
        }
    }
}

#[async_trait]
impl<B> FromRequest<B> for ClientClaims
where
    B: Send,
{
    type Rejection = Error;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let Extension(config) = Extension::<TokenConfig>::from_request(req)
            .await
            .expect("token config missing");

        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request(req)
                .await
                .map_err(|_| {
                    AuthenticationError::InvalidHeader("authorization header missing".to_string())
                })?;

        let token_data = jsonwebtoken::decode(bearer.token(), &config.dec_key, &config.validation)
            .map_err(|e| AuthenticationError::from(AuthTokenError::from(e)))?;

        Ok(token_data.claims)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceClaims {
    pub aud: Vec<String>,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,
    pub sub: String,
    #[serde(default)]
    pub scope: Vec<String>,
}

impl ServiceClaims {
    pub const DEFAULT_EXP_MIN: i64 = 30;

    fn new<A>(aud: A, sub: &str) -> Self
    where
        A: IntoIterator<Item = String>,
    {
        Self {
            aud: aud.into_iter().collect(),
            exp: Utc::now() + Duration::minutes(Self::DEFAULT_EXP_MIN),
            iat: Utc::now(),
            sub: sub.into(),
            scope: Vec::default(),
        }
    }

    fn with_scope<A, S>(aud: A, sub: &str, scope: S) -> Self
    where
        A: IntoIterator<Item = String>,
        S: IntoIterator<Item = String>,
    {
        let mut claims = Self::new(aud, sub);
        claims.scope = scope.into_iter().collect();

        claims
    }
}
