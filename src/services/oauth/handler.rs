use crate::{
    auth::{password::PasswordHasher, token::sign::TokenSigner},
    crypto::Secret,
    database::Collection,
    services::{
        client::model::ClientDocument, extract::Json, model::Response,
        service::model::ServiceDocument, token::AccessClaims,
    },
};

use super::{ClientSecret, OauthError};

use axum::extract::State;
use chrono::Duration;
use http::StatusCode;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TokenRequest {
    client_id: Uuid,
    client_secret: ClientSecret,
    grant_type: GrantType,
}

impl std::fmt::Debug for TokenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenRequest")
            .field("client_id", &self.client_id)
            .field("client_secret", &"********")
            .field("grant_type", &self.grant_type)
            .finish()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    ClientCredentials,

    #[serde(other)]
    Unsupported,
}

impl GrantType {
    /// Returns `true` if the grant type is [`Unsupported`].
    ///
    /// [`Unsupported`]: GrantType::Unsupported
    #[must_use]
    pub fn is_unsupported(&self) -> bool {
        matches!(self, Self::Unsupported)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TokenResponse {
    access_token: Secret<String>,
    token_type: TokenType,
    expires_in: u64,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"********")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    Bearer,
}

pub async fn create_token(
    State(services): State<Collection<ServiceDocument>>,
    State(clients): State<Collection<ClientDocument>>,
    State(signer): State<TokenSigner>,
    State(hasher): State<PasswordHasher>,
    Json(body): Json<TokenRequest>,
) -> crate::services::ServiceResult<Response<TokenResponse>> {
    if body.grant_type.is_unsupported() {
        return Err(OauthError::UnsupportedGrantType)?;
    }

    let client = clients
        .get_by_oauth_id(body.client_id)
        .await?
        .ok_or(OauthError::InvalidClient)?;

    let client_oauth = client.oauth.as_ref().unwrap();

    let secret_hash = client_oauth.secret.as_str();

    hasher
        .verify(body.client_secret, secret_hash)
        .map_err(|_| OauthError::InvalidClient)?;

    if client.locked {
        return Err(OauthError::InvalidClient)?;
    }
    if client_oauth.is_expired() {
        return Err(OauthError::InvalidClient)?;
    }

    clients.set_oauth_as_seen(body.client_id).await?;

    let service = services
        .get_by_id(client.service)
        .await
        .map_err(|_| OauthError::InternalError)?;

    let claims = AccessClaims::with_scope(service.audience, client.id, client.scope);
    let token = signer
        .sign(&claims)
        .await
        .map_err(|_| OauthError::InternalError)?;

    let response = TokenResponse {
        access_token: token,
        token_type: TokenType::Bearer,
        expires_in: Duration::minutes(AccessClaims::<String>::DEFAULT_EXP_MIN).num_seconds() as u64,
    };

    Ok(Response::with_status(StatusCode::OK, response))
}
