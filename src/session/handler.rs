use crate::{
    authentication::{password, token::TokenConfig},
    database::Database,
    error::Error,
    model::Status,
    session::{Scope, SessionClaims, SessionError},
    user::UserError,
};

use chrono::{serde::ts_seconds, DateTime, Utc};
use jsonwebtoken::encode;
use log::error;
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use warp::{http::StatusCode, reply, Rejection, Reply};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionResponse {
    user: String,
    token: String,
    #[serde(with = "ts_seconds")]
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    email: String,
    password: String,
}

pub async fn create(
    body: CreateRequest,
    db: Database,
    config: TokenConfig,
) -> std::result::Result<reply::Response, Rejection> {
    let user = match db.get_user(doc! {"email": body.email }).await {
        Ok(u) => u,
        Err(e) => match e {
            Error::User(e) => match e {
                UserError::NotFound => return Err(Error::from(SessionError::BadCredentials).into()),
                _ => return Err(e.into()),
            },
            _ => return Err(e.into()),
        },
    };

    if !user.verified {
        return Err(
            Error::from(SessionError::NotAllowed("user is not verified".to_string())).into(),
        );
    }
    if !user.can_login {
        return Err(Error::from(SessionError::NotAllowed(
            "user is not allowed to log in".to_string(),
        ))
        .into());
    }

    if password::verify_password(&body.password, &user.password).is_err() {
        return Err(Error::from(SessionError::BadCredentials).into());
    }

    let header = jsonwebtoken::Header::default();
    let audience = config.validation.aud.unwrap();
    let scope = Scope::from_roles(user.roles);
    let claims = SessionClaims::with_scope(audience, &user.id.to_hex(), scope);

    let token = match encode(&header, &claims, &config.enc_key) {
        Ok(t) => t,
        Err(e) => {
            error!("Error while encoding session token: {:?}", e);
            return Ok(
                Status::new(StatusCode::INTERNAL_SERVER_ERROR, "token encoding failed").into(),
            );
        }
    };

    let response = SessionResponse {
        user: user.id.to_hex(),
        token,
        expires_at: claims.exp,
    };

    db.set_user_session(user.id).await?;

    Ok(reply::with_status(reply::json(&response), StatusCode::CREATED).into_response())
}
