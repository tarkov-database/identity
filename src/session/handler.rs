use crate::{
    authentication::{
        password,
        token::{TokenClaims, TokenConfig},
    },
    database::Database,
    error::Error,
    extract::{SizedJson, TokenData},
    model::Response,
    session::{Scope, SessionClaims, SessionError},
    user::UserError,
};

use axum::extract::State;
use chrono::{serde::ts_seconds, DateTime, Duration, Utc};
use hyper::StatusCode;
use mongodb::bson::{doc, oid::ObjectId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    pub user: String,
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
    State(db): State<Database>,
    State(config): State<TokenConfig>,
    SizedJson(body): SizedJson<CreateRequest>,
) -> crate::Result<Response<SessionResponse>> {
    let user = match db.get_user(doc! {"email": body.email }).await {
        Ok(u) => u,
        Err(e) => match e {
            Error::User(e) => match e {
                UserError::NotFound => return Err(SessionError::BadCredentials.into()),
                _ => return Err(e.into()),
            },
            _ => return Err(e),
        },
    };

    let password = user.password.ok_or(SessionError::BadCredentials)?;

    if !user.verified {
        return Err(SessionError::NotAuthorized("user is not verified".to_string()).into());
    }
    if !user.can_login {
        return Err(
            SessionError::NotAuthorized("user is not authorized to log in".to_string()).into(),
        );
    }

    if password::verify_password(&body.password, &password).is_err() {
        return Err(SessionError::BadCredentials.into());
    }

    let audience = config.validation.aud.clone().unwrap();
    let scope = Scope::from_roles(user.roles);
    let claims = SessionClaims::with_scope(audience, &user.id.to_hex(), scope);

    let token = claims.encode(&config)?;

    let response = SessionResponse {
        user: user.id.to_hex(),
        token,
        expires_at: claims.exp,
    };

    db.set_user_session(user.id).await?;

    Ok(Response::with_status(StatusCode::CREATED, response))
}

pub async fn refresh(
    TokenData(claims): TokenData<SessionClaims>,
    State(db): State<Database>,
    State(config): State<TokenConfig>,
) -> crate::Result<Response<SessionResponse>> {
    let user_id = ObjectId::parse_str(&claims.sub).unwrap();

    let user = db.get_user(doc! {"_id": user_id }).await?;

    if !user.verified {
        return Err(SessionError::NotAuthorized("user is not verified".to_string()).into());
    }
    if !user.can_login {
        return Err(
            SessionError::NotAuthorized("user is not authorized to log in".to_string()).into(),
        );
    }

    let mut claims = claims;
    claims.set_expiration(Utc::now() + Duration::minutes(SessionClaims::DEFAULT_EXP_MIN));

    let token = claims.encode(&config)?;

    let response = SessionResponse {
        user: user.id.to_hex(),
        token,
        expires_at: claims.exp,
    };

    db.set_user_session(user.id).await?;

    Ok(Response::with_status(StatusCode::CREATED, response))
}
