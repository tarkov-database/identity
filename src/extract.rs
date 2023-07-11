use crate::{
    auth::{
        token::{verify::TokenVerifier, HeaderExt, Token, TokenError, TokenValidation},
        AuthenticationError,
    },
    error::Error,
    model::Status,
};

use std::net;

use axum::{
    async_trait,
    extract::{
        connect_info::ConnectInfo, rejection::JsonRejection, FromRef, FromRequest,
        FromRequestParts, TypedHeader,
    },
};
use headers::{authorization::Bearer, Authorization};
use http::{request::Parts, Request};
use hyper::StatusCode;
use serde::de::DeserializeOwned;

const X_FORWARDED_FOR: &str = "X-Forwarded-For";
const CF_CONNECTING_IP: &str = "CF-Connecting-IP";

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
            Err(rejection) => Err(Status::new(rejection.status(), rejection.body_text())),
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
            Err(rejection) => Err(Status::new(rejection.status(), rejection.body_text())),
        }
    }
}

pub struct TokenData<T>(pub T)
where
    T: Token;

#[async_trait]
impl<S, T> FromRequestParts<S> for TokenData<T>
where
    TokenVerifier: FromRef<S>,
    T: Token + TokenValidation + DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let verifier = TokenVerifier::from_ref(state);

        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
                .await
                .map_err(|_| {
                    AuthenticationError::InvalidHeader("authorization header missing".to_string())
                })?;

        let token = bearer.token();
        let (_, data) = verifier.verify::<T>(token).await?;

        Ok(Self(data))
    }
}

pub enum EitherTokenData<L, R>
where
    L: Token,
    R: Token,
{
    Left(L),
    Right(R),
}

#[async_trait]
impl<L, R, S> FromRequestParts<S> for EitherTokenData<L, R>
where
    TokenVerifier: FromRef<S>,
    L: Token + TokenValidation + DeserializeOwned + Send,
    R: Token + TokenValidation + DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let verifier = TokenVerifier::from_ref(state);

        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
                .await
                .map_err(|_| {
                    AuthenticationError::InvalidHeader("authorization header missing".to_string())
                })?;

        let token = bearer.token();
        let header = jsonwebtoken::decode_header(token).map_err(TokenError::from)?;

        let data = match header.token_type()? {
            v if v == L::TYPE => {
                let (_, data) = verifier.verify::<L>(token).await?;
                EitherTokenData::Left(data)
            }
            v if v == R::TYPE => {
                let (_, data) = verifier.verify::<R>(token).await?;
                EitherTokenData::Right(data)
            }
            _ => return Err(TokenError::Invalid)?,
        };

        Ok(data)
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

        match ConnectInfo::<net::SocketAddr>::from_request_parts(parts, state).await {
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
