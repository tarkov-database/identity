use crate::{
    authentication::{
        self,
        token::{TokenClaims, TokenConfig},
    },
    client::ClientError,
    database::Database,
    extract::{SizedJson, TokenData},
    model::Response,
    session::SessionClaims,
    token::{ClientClaims, ServiceClaims},
    user::UserError,
    utils::crypto::Aead256,
};

use std::iter::FromIterator;

use axum::extract::Extension;
use chrono::{serde::ts_seconds, DateTime, Utc};
use hyper::StatusCode;
use jsonwebtoken::{encode, EncodingKey};
use mongodb::bson::{doc, oid::ObjectId};
use serde::{Deserialize, Serialize};
use tracing::error;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenResponse {
    token: String,
    #[serde(with = "ts_seconds")]
    expires_at: DateTime<Utc>,
}

pub async fn get(
    TokenData(claims): TokenData<ClientClaims>,
    Extension(db): Extension<Database>,
    Extension(enc): Extension<Aead256>,
    Extension(config): Extension<TokenConfig>,
) -> crate::Result<Response<TokenResponse>> {
    let client_id = ObjectId::parse_str(&claims.sub).map_err(|_| ClientError::InvalidId)?;

    let client = db.get_client(doc! { "_id": client_id }).await?;
    let svc = db.get_service(doc! { "_id": client.service }).await?;

    if !client.unlocked {
        return Err(ClientError::Locked.into());
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

    let token = encode(&header, &claims, &key).map_err(authentication::token::TokenError::from)?;

    let response = TokenResponse {
        token,
        expires_at: claims.exp,
    };

    db.set_client_issued(client_id).await?;

    Ok(Response::with_status(StatusCode::CREATED, response))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    client: String,
}

pub async fn create(
    TokenData(claims): TokenData<SessionClaims>,
    SizedJson(body): SizedJson<CreateRequest>,
    Extension(db): Extension<Database>,
    Extension(config): Extension<TokenConfig>,
) -> crate::Result<Response<TokenResponse>> {
    let client_id = ObjectId::parse_str(&claims.sub).map_err(|_| ClientError::InvalidId)?;
    let user_id = ObjectId::parse_str(&claims.sub).map_err(|_| UserError::InvalidId)?;

    let client = db
        .get_client(doc! {"_id": client_id, "user": user_id })
        .await?;

    if !client.unlocked {
        return Err(ClientError::Locked.into());
    }

    let audience = config.validation.aud.clone().unwrap();
    let claims = ClientClaims::new(audience, &body.client, &claims.sub);

    let token = claims.encode(&config)?;

    let response = TokenResponse {
        token,
        expires_at: claims.exp,
    };

    db.set_client_issued(client_id).await?;

    Ok(Response::with_status(StatusCode::CREATED, response))
}
