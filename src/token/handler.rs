use crate::{
    auth::token::{sign::TokenSigner, TokenError},
    client::{ClientClaims, ClientError},
    database::Database,
    extract::EitherTokenData,
    model::Response,
    session::SessionClaims,
    token::AccessClaims,
    user::UserError,
};

use axum::extract::State;
use chrono::{serde::ts_seconds, DateTime, Utc};
use hyper::StatusCode;
use mongodb::bson::{doc, oid::ObjectId};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenResponse {
    token: String,
    #[serde(with = "ts_seconds")]
    expires_at: DateTime<Utc>,
}

pub async fn get(
    claims: EitherTokenData<ClientClaims, SessionClaims>,
    State(db): State<Database>,
    State(signer): State<TokenSigner>,
) -> crate::Result<Response<TokenResponse>> {
    let (token, expires_at) = match claims {
        EitherTokenData::Left(ClientClaims {
            ref jti, ref sub, ..
        }) => {
            let id = ObjectId::parse_str(sub).map_err(|_| ClientError::InvalidId)?;
            let client = db.get_client(doc! { "_id": id }).await?;
            match client.token {
                Some(t) if &Uuid::from(t.id) == jti => {}
                _ => return Err(TokenError::Invalid)?,
            }
            if client.locked {
                return Err(ClientError::Locked)?;
            }

            let user = db.get_user(doc! { "_id": client.user }).await?;
            if user.locked {
                return Err(UserError::Locked)?;
            }

            let service = db.get_service(doc! { "_id": client.service }).await?;

            let claims = AccessClaims::with_scope(service.audience, sub, client.scope);
            let token = signer.sign(&claims).await?;

            db.set_client_as_used(id).await?;

            (token, claims.exp)
        }
        EitherTokenData::Right(SessionClaims { jti, ref sub, .. }) => {
            let id = ObjectId::parse_str(sub).map_err(|_| UserError::InvalidId)?;
            let user = db.get_user(doc! { "_id": id }).await?;
            if user.locked {
                return Err(UserError::Locked)?;
            }
            if user.find_session(&jti.into()).is_none() {
                return Err(TokenError::Invalid)?;
            }

            let claims = AccessClaims::with_roles(&user.id.to_hex(), user.roles);
            let token = signer.sign(&claims).await?;

            (token, claims.exp)
        }
    };

    let response = TokenResponse { token, expires_at };

    Ok(Response::with_status(StatusCode::CREATED, response))
}
