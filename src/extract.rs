use crate::{
    authentication::{
        token::{TokenClaims, TokenConfig, TokenError},
        AuthenticationError,
    },
    error::Error,
    model::Status,
};

use std::{borrow::Cow, net};

use axum::{
    async_trait,
    extract::{
        rejection::{ContentLengthLimitRejection, JsonRejection, QueryRejection},
        FromRef, FromRequest, FromRequestParts, TypedHeader,
    },
    response::IntoResponse,
};
use headers::{authorization::Bearer, Authorization};
use http::{request::Parts, Request};
use hyper::StatusCode;
use serde::de::DeserializeOwned;

const CONTENT_LENGTH_LIMIT: u64 = 2048;

const X_FORWARDED_FOR: &str = "X-Forwarded-For";
const CF_CONNECTING_IP: &str = "CF-Connecting-IP";

/// JSON extractor with content length limit and custom error response
pub struct SizedJson<T>(pub T);

#[async_trait]
impl<S, B, T> FromRequest<S, B> for SizedJson<T>
where
    axum::Json<T>: FromRequest<S, B, Rejection = JsonRejection>,
    S: Send + Sync,
    B: Send + 'static,
{
    type Rejection = axum::response::Response;

    #[inline]
    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        match ContentLengthLimit::<Json<T>>::from_request(req, state).await {
            Ok(value) => Ok(Self(value.0 .0)),
            Err(err) => Err(err),
        }
    }
}

/// JSON extractor with custom error response
pub struct Json<T>(pub T);

#[async_trait]
impl<S, B, T> FromRequest<S, B> for Json<T>
where
    axum::Json<T>: FromRequest<S, B, Rejection = JsonRejection>,
    S: Send + Sync,
    B: Send + 'static,
{
    type Rejection = Status;

    #[inline]
    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(value) => Ok(Self(value.0)),
            Err(rejection) => {
                let (status, message): (_, Cow<'_, str>) = match rejection {
                    JsonRejection::JsonDataError(err) => {
                        (StatusCode::BAD_REQUEST, err.to_string().into())
                    }
                    JsonRejection::JsonSyntaxError(err) => {
                        (StatusCode::BAD_REQUEST, err.to_string().into())
                    }
                    JsonRejection::MissingJsonContentType(err) => {
                        (StatusCode::BAD_REQUEST, err.to_string().into())
                    }
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into()),
                };

                Err(Status::new(status, message))
            }
        }
    }
}

/// ContentLengthLimit extractor with custom error response
pub struct ContentLengthLimit<T, const N: u64 = CONTENT_LENGTH_LIMIT>(pub T);

#[async_trait]
impl<S, B, R, T, const N: u64> FromRequest<S, B> for ContentLengthLimit<T, N>
where
    R: axum::response::IntoResponse,
    axum::extract::ContentLengthLimit<T, N>:
        FromRequest<S, B, Rejection = ContentLengthLimitRejection<R>>,
    S: Send + Sync,
    B: Send + 'static,
{
    type Rejection = axum::response::Response;

    #[inline]
    async fn from_request(req: Request<B>, state: &S) -> Result<Self, Self::Rejection> {
        match axum::extract::ContentLengthLimit::<T, N>::from_request(req, state).await {
            Ok(value) => Ok(Self(value.0)),
            Err(rejection) => {
                let (status, message): (_, Cow<'_, str>) = match rejection {
                    ContentLengthLimitRejection::PayloadTooLarge(err) => {
                        (StatusCode::BAD_REQUEST, err.to_string().into())
                    }
                    ContentLengthLimitRejection::LengthRequired(err) => {
                        (StatusCode::BAD_REQUEST, err.to_string().into())
                    }
                    ContentLengthLimitRejection::Inner(err) => return Err(err.into_response()),
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into()),
                };

                Err(Status::new(status, message).into_response())
            }
        }
    }
}

pub struct Query<T>(pub T);

#[async_trait]
impl<S, T> FromRequestParts<S> for Query<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Status;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match axum::extract::Query::<T>::from_request_parts(parts, state).await {
            Ok(value) => Ok(Self(value.0)),
            Err(rejection) => {
                let (status, message): (_, Cow<'_, str>) = match rejection {
                    QueryRejection::FailedToDeserializeQueryString(_) => {
                        (StatusCode::BAD_REQUEST, "invalid query string".into())
                    }
                    _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into()),
                };

                Err(Status::new(status, message))
            }
        }
    }
}

pub struct TokenData<T>(pub T)
where
    T: TokenClaims;

#[async_trait]
impl<S, T> FromRequestParts<S> for TokenData<T>
where
    TokenConfig: FromRef<S>,
    T: TokenClaims,
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let config = TokenConfig::from_ref(state);

        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
                .await
                .map_err(|_| {
                    AuthenticationError::InvalidHeader("authorization header missing".to_string())
                })?;

        let token_data =
            jsonwebtoken::decode::<T>(bearer.token(), &config.dec_key, &config.validation)
                .map_err(|e| AuthenticationError::from(TokenError::from(e)))?;

        if token_data.claims.get_type() != &T::TOKEN_TYPE {
            return Err(AuthenticationError::from(TokenError::WrongType).into());
        }

        Ok(Self(token_data.claims))
    }
}

pub struct RemoteAddr(pub net::IpAddr);

#[async_trait]
impl<S> FromRequestParts<S> for RemoteAddr
where
    S: Send + Sync,
{
    type Rejection = Status;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let header = match &parts.headers {
            v if v.contains_key(CF_CONNECTING_IP) => Some((
                CF_CONNECTING_IP,
                v.get(CF_CONNECTING_IP).unwrap().to_str().map_err(|_| {
                    Status::new(
                        StatusCode::BAD_REQUEST,
                        format!(
                            "Header \"{}\" contains invalid characters",
                            CF_CONNECTING_IP
                        ),
                    )
                })?,
            )),
            v if v.contains_key(X_FORWARDED_FOR) => Some((
                X_FORWARDED_FOR,
                v.get(X_FORWARDED_FOR)
                    .unwrap()
                    .to_str()
                    .map_err(|_| {
                        Status::new(
                            StatusCode::BAD_REQUEST,
                            format!("Header \"{}\" contains invalid characters", X_FORWARDED_FOR),
                        )
                    })?
                    .split(',')
                    .next()
                    .ok_or_else(|| {
                        Status::new(
                            StatusCode::BAD_REQUEST,
                            format!("Header \"{}\" is invalid", X_FORWARDED_FOR),
                        )
                    })?,
            )),
            _ => None,
        };

        if let Some((name, value)) = header {
            let addr = value.trim().parse::<net::IpAddr>().map_err(|_| {
                Status::new(
                    StatusCode::BAD_REQUEST,
                    format!("Header \"{}\" contains a malformed IP address", name),
                )
            })?;

            if addr.is_unspecified() {
                return Err(Status::new(
                    StatusCode::BAD_REQUEST,
                    format!("Header \"{}\" contains an unspecified IP address", name),
                ));
            }

            return Ok(Self(addr));
        };

        match axum::extract::connect_info::ConnectInfo::<net::SocketAddr>::from_request_parts(
            parts, state,
        )
        .await
        {
            Ok(v) => Ok(Self(v.0.ip())),
            Err(_) => {
                return Err(Status::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error",
                ));
            }
        }
    }
}
