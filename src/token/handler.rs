use std::iter::FromIterator;

use crate::{
    authentication::token::TokenConfig,
    client::ClientError,
    database::Database,
    session::{SessionClaims, SessionError},
    token::{ClientClaims, ServiceClaims, TokenError},
    user::UserError,
    utils::crypto::Aead256,
};

use axum::{extract::Extension, Json};
use chrono::{serde::ts_seconds, DateTime, Utc};
use hyper::StatusCode;
use jsonwebtoken::{encode, EncodingKey};
use log::error;
use mongodb::bson::{doc, oid::ObjectId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenResponse {
    token: String,
    #[serde(with = "ts_seconds")]
    expires_at: DateTime<Utc>,
}

pub async fn get(
    claims: ClientClaims,
    Extension(db): Extension<Database>,
    Extension(enc): Extension<Aead256>,
    Extension(config): Extension<TokenConfig>,
) -> crate::Result<(StatusCode, Json<TokenResponse>)> {
    let client_id = match ObjectId::parse_str(&claims.sub) {
        Ok(v) => v,
        Err(_) => return Err(ClientError::InvalidId.into()),
    };

    dbg!("test!");

    let client = db.get_client(doc! { "_id": client_id }).await?;
    let svc = db.get_service(doc! { "_id": client.service }).await?;

    if !client.unlocked {
        return Err(SessionError::NotAllowed("client is locked".to_string()).into());
    }

    let header = jsonwebtoken::Header::default();

    let key = if let Some(s) = svc.secret {
        let secret = enc.decrypt(base64::decode_config(&s, base64::STANDARD).unwrap());
        EncodingKey::from_secret(&secret)
    } else {
        config.enc_key
    };

    let audience = if !svc.audience.is_empty() {
        svc.audience
    } else {
        Vec::from_iter(config.validation.aud.to_owned().unwrap())
    };

    let claims = ServiceClaims::with_scope(audience, &claims.sub, client.scope);

    let token = match encode(&header, &claims, &key) {
        Ok(t) => t,
        Err(e) => {
            error!("Error while encoding service token: {:?}", e);
            return Err(TokenError::Encoding.into());
        }
    };

    let response = TokenResponse {
        token,
        expires_at: claims.exp,
    };

    db.set_client_issued(client_id).await?;

    Ok((StatusCode::CREATED, Json(response)))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    client: String,
}

pub async fn create(
    claims: SessionClaims,
    Json(body): Json<CreateRequest>,
    Extension(db): Extension<Database>,
    Extension(config): Extension<TokenConfig>,
) -> crate::Result<(StatusCode, Json<TokenResponse>)> {
    let client_id = match ObjectId::parse_str(&body.client) {
        Ok(v) => v,
        Err(_) => return Err(ClientError::InvalidId.into()),
    };
    let user_id = match ObjectId::parse_str(&claims.sub) {
        Ok(v) => v,
        Err(_) => return Err(UserError::InvalidId.into()),
    };

    let client = db
        .get_client(doc! {"_id": client_id, "user": user_id })
        .await?;

    if !client.unlocked {
        return Err(SessionError::NotAllowed("client is locked".to_string()).into());
    }

    let header = jsonwebtoken::Header::default();
    let audience = config.validation.aud.unwrap();
    let claims = ClientClaims::new(audience, &body.client, &claims.sub);

    let token = match encode(&header, &claims, &config.enc_key) {
        Ok(t) => t,
        Err(e) => {
            error!("Error while encoding client token: {:?}", e);
            return Err(TokenError::Encoding.into());
        }
    };

    let response = TokenResponse {
        token,
        expires_at: claims.exp,
    };

    db.set_client_issued(client_id).await?;

    Ok((StatusCode::CREATED, Json(response)))
}
