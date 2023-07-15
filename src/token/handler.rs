use crate::{
    auth::token::{sign::TokenSigner, TokenError},
    database::Database,
    extract::TokenData,
    model::Response,
    session::SessionClaims,
    token::AccessClaims,
    user::{model::UserDocument, UserError},
};

use axum::extract::State;
use chrono::{serde::ts_seconds, DateTime, Utc};
use hyper::StatusCode;
use mongodb::bson::doc;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenResponse {
    token: String,
    #[serde(with = "ts_seconds")]
    expires_at: DateTime<Utc>,
}

pub async fn get(
    TokenData(claims): TokenData<SessionClaims>,
    State(db): State<Database>,
    State(signer): State<TokenSigner>,
) -> crate::Result<Response<TokenResponse>> {
    let users = db.collection::<UserDocument>();
    let user = users.get_by_id(claims.sub).await?;
    if user.locked {
        return Err(UserError::Locked)?;
    }
    if user.find_session(&claims.jti.into()).is_none() {
        return Err(TokenError::Invalid)?;
    }

    let claims = AccessClaims::with_roles(user.id, user.roles);
    let token = signer.sign(&claims).await?;

    let response = TokenResponse {
        token,
        expires_at: claims.exp,
    };

    Ok(Response::with_status(StatusCode::CREATED, response))
}
