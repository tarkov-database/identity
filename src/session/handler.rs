use crate::{
    auth::{
        password::Password,
        token::{sign::TokenSigner, TokenError},
    },
    database::{Collection, Database},
    error::Error,
    extract::{Json, TokenData},
    model::Response,
    session::{SessionClaims, SessionError},
    user::{
        model::{SessionDocument, UserDocument},
        UserError,
    },
};

use axum::extract::State;
use chrono::{serde::ts_seconds, DateTime, Duration, Utc};
use hyper::StatusCode;
use mongodb::bson::{doc, oid::ObjectId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    pub user_id: String,
    pub token: String,
    #[serde(with = "ts_seconds")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    email: String,
    password: String,
}

pub async fn create(
    State(users): State<Collection<UserDocument>>,
    State(signer): State<TokenSigner>,
    State(password): State<Password>,
    Json(body): Json<CreateRequest>,
) -> crate::Result<Response<SessionResponse>> {
    let user = match users.get_by_email(&body.email).await {
        Ok(u) => u,
        Err(e) => match e {
            Error::User(e) => match e {
                UserError::NotFound => return Err(SessionError::BadCredentials.into()),
                _ => return Err(e.into()),
            },
            _ => return Err(e),
        },
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

    if password.verify(&body.password, &password_hash).is_err() {
        return Err(SessionError::BadCredentials.into());
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
) -> crate::Result<Response<SessionResponse>> {
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
