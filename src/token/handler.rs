use std::iter::FromIterator;

use crate::{
    authentication::token::TokenConfig,
    client::ClientError,
    database::Database,
    error::Error,
    model::Status,
    session::{SessionClaims, SessionError},
    token::{ClientClaims, ServiceClaims},
    user::UserError,
    utils::crypto::Aead256,
};

use chrono::{serde::ts_seconds, DateTime, Utc};
use jsonwebtoken::{encode, EncodingKey};
use log::error;
use mongodb::bson::{doc, oid::ObjectId};
use serde::{Deserialize, Serialize};
use warp::{http::StatusCode, reply, Rejection, Reply};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenResponse {
    token: String,
    #[serde(with = "ts_seconds")]
    expires_at: DateTime<Utc>,
}

pub async fn get(
    claims: ClientClaims,
    db: Database,
    enc: Aead256,
    config: TokenConfig,
) -> std::result::Result<reply::Response, Rejection> {
    let client_id = match ObjectId::parse_str(&claims.sub) {
        Ok(v) => v,
        Err(_) => return Err(Error::from(ClientError::InvalidId).into()),
    };

    dbg!("test!");

    let client = db.get_client(doc! { "_id": client_id }).await?;
    let svc = db.get_service(doc! { "_id": client.service }).await?;

    if !client.unlocked {
        return Err(Error::from(SessionError::NotAllowed("client is locked".to_string())).into());
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
            return Ok(
                Status::new(StatusCode::INTERNAL_SERVER_ERROR, "token encoding failed").into(),
            );
        }
    };

    let response = TokenResponse {
        token,
        expires_at: claims.exp,
    };

    db.set_client_issued(client_id).await?;

    Ok(reply::with_status(reply::json(&response), StatusCode::CREATED).into_response())
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    client: String,
}

pub async fn create(
    claims: SessionClaims,
    body: CreateRequest,
    db: Database,
    config: TokenConfig,
) -> std::result::Result<reply::Response, Rejection> {
    let client_id = match ObjectId::parse_str(&body.client) {
        Ok(v) => v,
        Err(_) => return Err(Error::from(ClientError::InvalidId).into()),
    };
    let user_id = match ObjectId::parse_str(&claims.sub) {
        Ok(v) => v,
        Err(_) => return Err(Error::from(UserError::InvalidId).into()),
    };

    let client = db
        .get_client(doc! {"_id": client_id, "user": user_id })
        .await?;

    if !client.unlocked {
        return Err(Error::from(SessionError::NotAllowed("client is locked".to_string())).into());
    }

    let header = jsonwebtoken::Header::default();
    let audience = config.validation.aud.unwrap();
    let claims = ClientClaims::new(audience, &body.client, &claims.sub);

    let token = match encode(&header, &claims, &config.enc_key) {
        Ok(t) => t,
        Err(e) => {
            error!("Error while encoding client token: {:?}", e);
            return Ok(
                Status::new(StatusCode::INTERNAL_SERVER_ERROR, "token encoding failed").into(),
            );
        }
    };

    let response = TokenResponse {
        token,
        expires_at: claims.exp,
    };

    db.set_client_issued(client_id).await?;

    Ok(reply::with_status(reply::json(&response), StatusCode::CREATED).into_response())
}
