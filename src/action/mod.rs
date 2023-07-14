mod handler;
mod routes;

use crate::{
    auth::token::{sign::TokenSigner, Token, TokenType, TokenValidation, LEEWAY},
    error, mail,
    model::Status,
};

use std::{collections::HashMap, marker::PhantomData};

use chrono::{serde::ts_seconds, DateTime, Duration, Utc};
use hyper::StatusCode;
use mongodb::bson::{oid::ObjectId, serde_helpers::serialize_object_id_as_hex_string};
use serde::{Deserialize, Serialize};

pub use routes::routes;

#[derive(Debug, thiserror::Error)]
pub enum ActionError {
    #[error("invalid token")]
    InvalidToken,
    #[error("already verified")]
    AlreadyVerified,
    #[error("user not verified")]
    NotVerified,
}

impl error::ErrorResponse for ActionError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        match self {
            ActionError::InvalidToken | ActionError::AlreadyVerified => StatusCode::BAD_REQUEST,
            ActionError::NotVerified => StatusCode::FORBIDDEN,
        }
    }

    fn error_response(&self) -> Self::Response {
        Status::new(self.status_code(), self.to_string())
    }
}

pub trait ActionType {
    const AUDIENCE: &'static str;
}

pub struct Verify;

impl ActionType for Verify {
    const AUDIENCE: &'static str = "identity/action/verify";
}

pub struct Reset;

impl ActionType for Reset {
    const AUDIENCE: &'static str = "identity/action/reset";
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionClaims<T> {
    pub aud: String,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub nbf: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,
    #[serde(serialize_with = "serialize_object_id_as_hex_string")]
    pub sub: ObjectId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    #[serde(skip)]
    marker: PhantomData<T>,
}

impl<T: ActionType> Default for ActionClaims<T> {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            aud: T::AUDIENCE.into(),
            exp: now + Duration::hours(1),
            nbf: now,
            iat: now,
            sub: ObjectId::default(),
            email: None,
            marker: PhantomData,
        }
    }
}

impl ActionClaims<Verify> {
    pub fn new_verify(user_id: ObjectId, email: String) -> Self {
        Self {
            sub: user_id,
            email: Some(email),
            ..Self::default()
        }
    }
}

impl ActionClaims<Reset> {
    pub fn new_reset(user_id: ObjectId) -> Self {
        Self {
            sub: user_id,
            ..Self::default()
        }
    }
}

impl<T: ActionType> Token for ActionClaims<T> {
    const TYPE: TokenType = TokenType::Action;

    fn expires_at(&self) -> DateTime<Utc> {
        self.exp
    }

    fn not_before(&self) -> DateTime<Utc> {
        self.nbf
    }

    fn issued_at(&self) -> DateTime<Utc> {
        self.iat
    }
}

impl<T: ActionType> TokenValidation for ActionClaims<T> {
    fn validation(alg: jsonwebtoken::Algorithm) -> jsonwebtoken::Validation {
        let mut validation = jsonwebtoken::Validation::new(alg);
        validation.leeway = LEEWAY;
        validation.set_required_spec_claims(&["exp", "nbf", "sub", "aud", "iat"]);
        validation.set_audience(&[T::AUDIENCE]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation
    }
}

pub async fn send_verification_mail(
    addr: String,
    user_id: ObjectId,
    client: mail::Client,
    signer: TokenSigner,
) -> crate::Result<()> {
    let claims = ActionClaims::new_verify(user_id, addr.clone());
    let token = signer.sign(&claims).await?;

    const TEMPLATE_NAME: &str = "identity.action.verify";
    const SUBJECT: &str = "Email verification required";

    let mut vars = HashMap::with_capacity(1);
    vars.insert("token".to_string(), token);

    client
        .send_template(&addr, SUBJECT, TEMPLATE_NAME, vars)
        .await?;

    Ok(())
}

async fn send_reset_mail(
    addr: String,
    user_id: ObjectId,
    client: mail::Client,
    signer: TokenSigner,
) -> crate::Result<()> {
    let claims = ActionClaims::new_reset(user_id);
    let token = signer.sign(&claims).await?;

    const TEMPLATE_NAME: &str = "identity.action.reset";
    const SUBJECT: &str = "Password reset";

    let mut vars = HashMap::with_capacity(1);
    vars.insert("token".to_string(), token);

    client
        .send_template(&addr, SUBJECT, TEMPLATE_NAME, vars)
        .await?;

    Ok(())
}
