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
}

impl warp::reject::Reject for ActionError {}

impl error::ErrorResponse for ActionError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        match self {
            ActionError::Invalid | ActionError::AlreadyVerified => StatusCode::BAD_REQUEST,
        }
    }

    fn error_response(&self) -> Self::Response {
        Status::new(self.status_code(), self.to_string())
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
}

impl ActionClaims {
    pub const DEFAULT_EXP_HOURS: i64 = 3 * 24;

    fn with_email<A>(aud: A, sub: &str, email: &str) -> Self
    where
        A: IntoIterator<Item = String>,
    {
        Self {
            aud: aud.into_iter().collect(),
            exp: Utc::now() + Duration::hours(Self::DEFAULT_EXP_HOURS),
            iat: Utc::now(),
            sub: sub.into(),
            email: Some(email.into()),
        }
    }
}

pub async fn send_verification_request(
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
