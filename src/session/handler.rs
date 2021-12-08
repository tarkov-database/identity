use crate::{
    authentication::{password, token::TokenConfig},
    database::Database,
    error::Error,
    extract::SizedJson,
    model::Response,
    session::{Scope, SessionClaims, SessionError},
    user::UserError,
};

use axum::extract::Extension;
use chrono::{serde::ts_seconds, DateTime, Utc};
use hyper::StatusCode;
use jsonwebtoken::encode;
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use tracing::error;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
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
    SizedJson(body): SizedJson<CreateRequest>,
    Extension(db): Extension<Database>,
    Extension(config): Extension<TokenConfig>,
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

    if !user.verified {
        return Err(SessionError::NotAllowed("user is not verified".to_string()).into());
    }
    if !user.can_login {
        return Err(SessionError::NotAllowed("user is not allowed to log in".to_string()).into());
    }

    if password::verify_password(&body.password, &user.password).is_err() {
        return Err(SessionError::BadCredentials.into());
    }

    let header = jsonwebtoken::Header::default();
    let audience = config.validation.aud.unwrap();
    let scope = Scope::from_roles(user.roles);
    let claims = SessionClaims::with_scope(audience, &user.id.to_hex(), scope);

    let token = match encode(&header, &claims, &config.enc_key) {
        Ok(t) => t,
        Err(e) => {
            error!("Error while encoding session token: {:?}", e);
            return Err(SessionError::Encoding.into());
        }
    };

    let response = SessionResponse {
        user: user.id.to_hex(),
        token,
        expires_at: claims.exp,
    };

    db.set_user_session(user.id).await?;

    Ok(Response::with_status(StatusCode::CREATED, response))
}
