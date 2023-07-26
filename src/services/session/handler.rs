use crate::{
    auth::{
        password::PasswordHasher,
        token::{sign::TokenSigner, TokenError},
    },
    crypto::Secret,
    database::Collection,
    services::{
        error::Error,
        extract::{Json, TokenData},
        model::{EmailAddr, Response},
        session::{SessionClaims, SessionError},
        user::{
            model::{SessionDocument, UserDocument},
            UserError,
        },
        ServiceResult,
    },
};

use axum::extract::State;
use chrono::{serde::ts_seconds, DateTime, Duration, Utc};
use hyper::StatusCode;
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    pub user_id: String,
    pub token: Secret<String>,
    #[serde(with = "ts_seconds")]
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Debug for SessionResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionResponse")
            .field("user_id", &self.user_id)
            .field("token", &"********")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    email: EmailAddr,
    password: Secret<String>,
}

impl std::fmt::Debug for CreateRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateRequest")
            .field("email", &self.email)
            .field("password", &"********")
            .finish()
    }
}

pub async fn create(
    State(users): State<Collection<UserDocument>>,
    State(signer): State<TokenSigner>,
    State(hasher): State<PasswordHasher>,
    Json(body): Json<CreateRequest>,
) -> ServiceResult<Response<SessionResponse>> {
    let user = match users.get_by_email(&body.email).await {
        Ok(u) => u,
        Err(Error::User(UserError::NotFound)) => {
            return Err(SessionError::BadCredentials)?;
        }
        Err(e) => return Err(e),
    };

    let password_hash = user.password.ok_or(SessionError::BadCredentials)?;

    if user.locked {
        return Err(UserError::Locked)?;
    }
    if !user.verified {
        return Err(UserError::NotVerified)?;
    }
    if !user.can_login {
        return Err(UserError::LoginNotAllowed)?;
    }

    if hasher.verify(body.password, password_hash).is_err() {
        return Err(SessionError::BadCredentials)?;
    }

    let session = SessionDocument::new();

    let claims = SessionClaims::new(session.id, user.id);
    let token = signer.sign(&claims).await?;

    let response = SessionResponse {
        user_id: user.id.to_hex(),
        token,
        expires_at: claims.exp,
    };

    users.set_session(user.id, session).await?;

    Ok(Response::with_status(StatusCode::CREATED, response))
}

pub async fn refresh(
    TokenData(claims): TokenData<SessionClaims>,
    State(users): State<Collection<UserDocument>>,
    State(signer): State<TokenSigner>,
) -> ServiceResult<Response<SessionResponse>> {
    let user = users.get_by_id(claims.sub).await?;

    if user.locked {
        return Err(UserError::Locked)?;
    }
    if !user.verified {
        return Err(UserError::NotVerified)?;
    }
    if !user.can_login {
        return Err(UserError::LoginNotAllowed)?;
    }
    if user.find_session(&claims.jti.into()).is_none() {
        return Err(TokenError::Invalid)?;
    }

    let mut claims = claims;
    claims.set_expiration(Utc::now() + Duration::minutes(SessionClaims::DEFAULT_EXP_MIN));

    let token = signer.sign(&claims).await?;

    let response = SessionResponse {
        user_id: user.id.to_hex(),
        token,
        expires_at: claims.exp,
    };

    let session = SessionDocument::with_id(claims.jti);

    users.set_session(user.id, session).await?;

    Ok(Response::with_status(StatusCode::CREATED, response))
}
