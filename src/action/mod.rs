mod filter;
mod handler;

use crate::{authentication::token::TokenConfig, error, mail, model::Status, Result};

use std::collections::HashMap;

use chrono::{serde::ts_seconds, DateTime, Duration, Utc};
use jsonwebtoken::encode;
use serde::{Deserialize, Serialize};
use warp::hyper::StatusCode;

pub use filter::filters;

#[derive(Debug, thiserror::Error)]
pub enum ActionError {
    #[error("invalid token")]
    Invalid,
    #[error("already verified")]
    AlreadyVerified,
    #[error("user not verified")]
    NotVerified,
}

impl warp::reject::Reject for ActionError {}

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

pub async fn send_verification_mail(
    addr: &str,
    user_id: &str,
    client: mail::Client,
    config: TokenConfig,
) -> Result<()> {
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
) -> Result<()> {
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
