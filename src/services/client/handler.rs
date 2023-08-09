use crate::{
    auth::{
        password::{PasswordError, PasswordHasher},
        AuthError,
    },
    crypto::{self},
    database::Collection,
    services::{
        error::QueryError,
        extract::{Json, Query, TokenData},
    },
    services::{
        model::{List, ListOptions, Response, Status},
        oauth::ClientSecret,
    },
    services::{
        service::model::ServiceDocument,
        token::{AccessClaims, Scope},
        ServiceResult,
    },
};

use super::{
    model::{ClientDocument, ClientName, OauthDocument},
    ClientError, CREDENTIALS_MAX_VALIDITY,
};

use std::iter::once;

use axum::extract::{Path, State};
use chrono::{serde::ts_seconds, DateTime, Duration, Utc};
use hyper::StatusCode;
use mongodb::bson::{
    self, doc, oid::ObjectId, serde_helpers::serialize_object_id_as_hex_string, Document,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientResponse {
    #[serde(serialize_with = "serialize_object_id_as_hex_string")]
    pub id: ObjectId,
    #[serde(serialize_with = "serialize_object_id_as_hex_string")]
    pub user: ObjectId,
    #[serde(serialize_with = "serialize_object_id_as_hex_string")]
    pub service: ObjectId,
    pub name: ClientName,
    pub scope: Vec<String>,
    pub locked: bool,
    pub oauth: Option<OauthResponse>,
    #[serde(with = "ts_seconds")]
    pub last_modified: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub created: DateTime<Utc>,
}

impl From<ClientDocument> for ClientResponse {
    fn from(doc: ClientDocument) -> Self {
        Self {
            id: doc.id,
            user: doc.user,
            service: doc.service,
            name: doc.name,
            scope: doc.scope,
            locked: doc.locked,
            oauth: doc.oauth.map(OauthResponse::from),
            last_modified: doc.last_modified,
            created: doc.created,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OauthResponse {
    pub id: Uuid,
    #[serde(with = "ts_seconds")]
    pub last_seen: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub expires: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub issued: DateTime<Utc>,
}

impl From<OauthDocument> for OauthResponse {
    fn from(doc: OauthDocument) -> Self {
        Self {
            id: doc.id.into(),
            last_seen: doc.last_seen,
            expires: doc.expires,
            issued: doc.issued,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Filter {
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<ObjectId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<ObjectId>,
}

impl From<&Filter> for bson::Document {
    fn from(filter: &Filter) -> Self {
        bson::to_document(filter).unwrap()
    }
}

pub async fn list(
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    Query(filter): Query<Filter>,
    Query(opts): Query<ListOptions>,
    State(clients): State<Collection<ClientDocument>>,
) -> ServiceResult<Response<List<ClientResponse>>> {
    if !claims.contains_scopes(once(&Scope::ClientRead)) {
        return Err(AuthError::InsufficientPermission)?;
    };

    let mut filter = bson::Document::from(&filter);
    if !claims.contains_scopes(once(&Scope::UserRead)) {
        filter.insert("user", claims.sub);
    }

    let (clients, total) = clients.get_all(filter, Some(opts.into())).await?;
    let list = List::new(total, clients);

    Ok(Response::new(list))
}

pub async fn get_by_id(
    Path(id): Path<ObjectId>,
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    State(clients): State<Collection<ClientDocument>>,
) -> ServiceResult<Response<ClientResponse>> {
    if !claims.contains_scopes(once(&Scope::ClientRead)) {
        return Err(AuthError::InsufficientPermission)?;
    };

    let client = if claims.contains_scopes(once(&Scope::UserRead)) {
        clients.get_by_id(id).await?
    } else {
        clients.get_by_id_and_user(id, claims.sub).await?
    };

    Ok(Response::with_status(StatusCode::OK, client.into()))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    user: Option<ObjectId>,
    name: ClientName,
    service: ObjectId,
    scope: Option<Vec<String>>,
}

pub async fn create(
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    State(clients): State<Collection<ClientDocument>>,
    State(services): State<Collection<ServiceDocument>>,
    Json(body): Json<CreateRequest>,
) -> ServiceResult<Response<ClientResponse>> {
    if !claims.contains_scopes([&Scope::ClientWrite, &Scope::ServiceRead]) {
        return Err(AuthError::InsufficientPermission)?;
    };

    let user_id = if let Some(id) = body.user {
        (id == claims.sub || claims.contains_scopes(once(&Scope::UserWrite)))
            .then_some(id)
            .ok_or(AuthError::InsufficientPermission)?
    } else {
        claims.sub
    };

    let service = services.get_by_id(body.service).await?;

    let client = ClientDocument {
        id: ObjectId::new(),
        user: user_id,
        name: body.name,
        service: service.id,
        scope: service.scope_default,
        locked: false,
        oauth: None,
        last_modified: Utc::now(),
        created: Utc::now(),
    };

    clients.insert(&client).await?;

    Ok(Response::with_status(StatusCode::CREATED, client.into()))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRequest {
    user: Option<ObjectId>,
    name: Option<ClientName>,
    scope: Option<Vec<String>>,
    locked: Option<bool>,
}

pub async fn update(
    Path(id): Path<ObjectId>,
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    State(clients): State<Collection<ClientDocument>>,
    Json(body): Json<UpdateRequest>,
) -> ServiceResult<Response<ClientResponse>> {
    if !claims.contains_scopes(once(&Scope::ClientWrite)) {
        return Err(AuthError::InsufficientPermission)?;
    };

    let mut doc = Document::new();
    if let Some(v) = body.user {
        if !claims.contains_scopes(once(&Scope::UserWrite)) {
            return Err(AuthError::InsufficientPermission)?;
        }
        doc.insert("user", v);
    }
    if let Some(v) = body.locked {
        if !claims.contains_scopes(once(&Scope::UserWrite)) {
            return Err(AuthError::InsufficientPermission)?;
        }
        doc.insert("locked", v);
    }
    if let Some(v) = body.name {
        doc.insert("name", v.as_str());
    }
    if let Some(v) = body.scope {
        doc.insert("scope", v);
    }
    if doc.is_empty() {
        return Err(QueryError::InvalidBody)?;
    }

    let user = if !claims.contains_scopes(once(&Scope::UserWrite)) {
        Some(claims.sub)
    } else {
        None
    };

    let doc = clients.update(id, user, doc).await?;

    Ok(Response::with_status(StatusCode::OK, doc.into()))
}

pub async fn delete(
    Path(id): Path<ObjectId>,
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    State(clients): State<Collection<ClientDocument>>,
) -> ServiceResult<Status> {
    if !claims.contains_scopes(once(&Scope::ClientWrite)) {
        return Err(AuthError::InsufficientPermission)?;
    }

    let user = if !claims.contains_scopes(once(&Scope::UserWrite)) {
        Some(claims.sub)
    } else {
        None
    };

    clients.delete(id, user).await?;

    Ok(Status::new(StatusCode::OK, "client deleted"))
}

const fn default_validity() -> u64 {
    CREDENTIALS_MAX_VALIDITY
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialsRequest {
    /// Period of validity in seconds
    #[serde(default = "default_validity")]
    validity: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialsResponse {
    client_id: Uuid,
    secret: ClientSecret,
    #[serde(with = "ts_seconds")]
    expires: DateTime<Utc>,
}

impl std::fmt::Debug for CredentialsResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialsResponse")
            .field("client_id", &self.client_id)
            .field("secret", &"********")
            .field("expires", &self.expires)
            .finish()
    }
}

pub async fn create_credentials(
    Path(id): Path<ObjectId>,
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    State(clients): State<Collection<ClientDocument>>,
    State(hasher): State<PasswordHasher>,
    Json(body): Json<CredentialsRequest>,
) -> ServiceResult<Response<CredentialsResponse>> {
    if !claims.contains_scopes(once(&Scope::ClientWrite)) {
        return Err(AuthError::InsufficientPermission)?;
    };

    let client = clients.get_by_id_and_user(id, claims.sub).await?;

    if client.locked {
        return Err(ClientError::Locked)?;
    }

    let validity = Duration::seconds(body.validity as i64);

    if validity > Duration::seconds(CREDENTIALS_MAX_VALIDITY as i64)
        || validity < Duration::seconds(60)
    {
        return Err(ClientError::InvalidValidity)?;
    }

    let expires = Utc::now() + validity;

    let client_id = uuid::Builder::from_random_bytes(crypto::gen::random_bytes()).into_uuid();
    let client_secret = ClientSecret::new();

    let doc = OauthDocument {
        id: client_id.into(),
        secret: hasher.hash(&client_secret).map_err(PasswordError::Hash)?,
        last_seen: Default::default(),
        expires,
        issued: Utc::now(),
    };

    clients.set_oauth(id, doc).await?;

    let response = CredentialsResponse {
        client_id,
        secret: client_secret,
        expires,
    };

    Ok(Response::with_status(StatusCode::CREATED, response))
}
