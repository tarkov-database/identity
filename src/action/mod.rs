mod handler;
mod routes;

use crate::{
    authentication::{
        token::{TokenConfig, TokenError},
        AuthenticationError,
    },
    error::{self, Error},
    mail,
    model::Status,
};

use std::collections::HashMap;

use axum::{
    async_trait,
    extract::{Extension, FromRequest, RequestParts, TypedHeader},
};
use chrono::{serde::ts_seconds, DateTime, Duration, Utc};
use headers::{authorization::Bearer, Authorization};
use hyper::StatusCode;
use jsonwebtoken::encode;
use serde::{Deserialize, Serialize};

pub use routes::routes;

#[derive(Debug, thiserror::Error)]
pub enum ActionError {
    #[error("invalid token")]
    Invalid,
    #[error("already verified")]
    AlreadyVerified,
    #[error("user not verified")]
    NotVerified,
}

impl error::ErrorResponse for ActionError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        match self {
            ActionError::Invalid | ActionError::AlreadyVerified => StatusCode::BAD_REQUEST,
            ActionError::NotVerified => StatusCode::FORBIDDEN,
        }
    }

    fn error_response(&self) -> Self::Response {
        Status::new(self.status_code(), self.to_string())
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ActionType {
    Verify,
    Reset,
}

impl ActionType {
    const fn expiration_time(&self) -> std::time::Duration {
        match self {
            ActionType::Verify => std::time::Duration::from_secs(3 * 60 * 60 * 24),
            ActionType::Reset => std::time::Duration::from_secs(30 * 60),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionClaims {
    pub aud: Vec<String>,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,
    pub sub: String,
    pub email: Option<String>,
    pub r#type: ActionType,
}

impl ActionClaims {
    fn new<A>(aud: A, sub: &str, r#type: ActionType) -> Self
    where
        A: IntoIterator<Item = String>,
    {
        Self {
            aud: aud.into_iter().collect(),
            exp: Utc::now() + Duration::from_std(r#type.expiration_time()).unwrap(),
            iat: Utc::now(),
            sub: sub.into(),
            email: None,
            r#type,
        }
    }

    fn with_email<A>(aud: A, sub: &str, email: &str) -> Self
    where
        A: IntoIterator<Item = String>,
    {
        let mut claims = Self::new(aud, sub, ActionType::Verify);
        claims.email = Some(email.into());

        claims
    }
}

#[async_trait]
impl<B> FromRequest<B> for ActionClaims
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
            .map_err(|e| AuthenticationError::from(TokenError::from(e)))?;

        Ok(token_data.claims)
    }
}

pub async fn send_verification_mail(
    addr: &str,
    user_id: &str,
    client: mail::Client,
    config: TokenConfig,
) -> crate::Result<()> {
    let header = jsonwebtoken::Header::default();
    let audience = config.validation.aud.unwrap();
    let claims = ActionClaims::with_email(audience, user_id, addr);

    let token = encode(&header, &claims, &config.enc_key).unwrap();

    const TEMPLATE_NAME: &str = "identity.action.verify";
    const SUBJECT: &str = "Email verification required";

    let mut vars = HashMap::with_capacity(1);
    vars.insert("token".to_string(), token);

    client
        .send_template(addr, SUBJECT, TEMPLATE_NAME, vars)
        .await?;

    Ok(())
}

async fn send_reset_mail(
    addr: &str,
    user_id: &str,
    client: mail::Client,
    config: TokenConfig,
) -> crate::Result<()> {
    let header = jsonwebtoken::Header::default();
    let audience = config.validation.aud.unwrap();
    let claims = ActionClaims::new(audience, user_id, ActionType::Reset);

    let token = encode(&header, &claims, &config.enc_key).unwrap();

    const TEMPLATE_NAME: &str = "identity.action.reset";
    const SUBJECT: &str = "Password reset";

    let mut vars = HashMap::with_capacity(1);
    vars.insert("token".to_string(), token);

    client
        .send_template(addr, SUBJECT, TEMPLATE_NAME, vars)
        .await?;

    Ok(())
}
