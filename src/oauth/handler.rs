use crate::{
    auth::{password::Password, token::sign::TokenSigner},
    client::model::ClientDocument,
    crypto::Secret,
    database::Collection,
    extract::Json,
    model::Response,
    service::model::ServiceDocument,
    token::AccessClaims,
};

use super::{OauthError, CLIENT_SECRET_LENGTH};

use axum::extract::State;
use chrono::Duration;
use http::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TokenRequest {
    client_id: String,
    client_secret: Secret<CLIENT_SECRET_LENGTH>,
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TokenResponse {
    access_token: String,
    token_type: TokenType,
    expires_in: u64,
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
    State(password): State<Password>,
    Json(body): Json<TokenRequest>,
) -> crate::Result<Response<TokenResponse>> {
    if body.grant_type.is_unsupported() {
        return Err(OauthError::UnsupportedGrantType)?;
    }

    let client = clients
        .get_by_oauth_id(&body.client_id)
        .await?
        .ok_or(OauthError::InvalidClient)?;

    let client_oauth = client.oauth.as_ref().unwrap();

    let secret_hash = client_oauth.secret.as_str();

    password
        .verify(body.client_secret, secret_hash)
        .map_err(|_| OauthError::InvalidClient)?;

    if client.locked {
        return Err(OauthError::InvalidClient)?;
    }
    if client_oauth.is_expired() {
        return Err(OauthError::InvalidClient)?;
    }

    clients.set_oauth_as_seen(&body.client_id).await?;

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
