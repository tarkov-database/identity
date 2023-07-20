use crate::{
    auth::{password::Password, AuthError},
    crypto::{self, Secret},
    database::Collection,
    services::model::{List, ListOptions, Response, Status},
    services::{
        error::QueryError,
        extract::{Json, Query, TokenData},
    },
    services::{
        oauth::{CLIENT_ID_LENGTH, CLIENT_SECRET_LENGTH},
        service::model::ServiceDocument,
        token::{AccessClaims, Scope},
        ServiceResult,
    },
};

use super::{
    model::{ClientDocument, OauthDocument},
    ClientError, CREDENTIALS_MAX_VALIDITY,
};

use axum::extract::{Path, State};
use chrono::{serde::ts_seconds, DateTime, Duration, Utc};
use hyper::StatusCode;
use mongodb::bson::{doc, oid::ObjectId, to_document, Document};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientResponse {
    pub id: String,
    pub user: String,
    pub service: String,
    pub name: String,
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
            id: doc.id.to_hex(),
            user: doc.user.to_hex(),
            service: doc.service.to_hex(),
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
    pub id: String,
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
            id: doc.id,
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
    approved: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<ObjectId>,
}

pub async fn list(
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    Query(filter): Query<Filter>,
    Query(opts): Query<ListOptions>,
    State(clients): State<Collection<ClientDocument>>,
) -> ServiceResult<Response<List<ClientResponse>>> {
    let user = if !claims.scope.contains(&Scope::ClientRead) {
        Some(&claims.sub)
    } else {
        filter.user.as_ref()
    };

    let mut filter_doc = to_document(&filter).unwrap();
    if let Some(id) = user {
        filter_doc.insert("user", id);
    }
    if let Some(id) = filter.service {
        filter_doc.insert("service", id);
    }

    let (clients, total) = clients.get_all(filter_doc, Some(opts.into())).await?;
    let list = List::new(total, clients);

    Ok(Response::new(list))
}

pub async fn get_by_id(
    Path(id): Path<ObjectId>,
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    State(clients): State<Collection<ClientDocument>>,
) -> ServiceResult<Response<ClientResponse>> {
    let client = if claims.scope.contains(&Scope::ClientRead) {
        clients.get_by_id_and_user(id, claims.sub).await?
    } else {
        clients.get_by_id(id).await?
    };

    Ok(Response::with_status(StatusCode::OK, client.into()))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    user: Option<ObjectId>,
    name: String,
    service: ObjectId,
    scope: Option<Vec<String>>,
}

pub async fn create(
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    State(clients): State<Collection<ClientDocument>>,
    State(services): State<Collection<ServiceDocument>>,
    Json(body): Json<CreateRequest>,
) -> ServiceResult<Response<ClientResponse>> {
    let user_id = if let Some(id) = body.user {
        if !claims.scope.contains(&Scope::ClientWrite) && claims.sub != id {
            return Err(AuthError::InsufficientPermission.into());
        }
        id
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
    name: Option<String>,
    scope: Option<Vec<String>>,
    locked: Option<bool>,
}

pub async fn update(
    Path(id): Path<ObjectId>,
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    State(clients): State<Collection<ClientDocument>>,
    Json(body): Json<UpdateRequest>,
) -> ServiceResult<Response<ClientResponse>> {
    let mut doc = Document::new();
    if claims.scope.contains(&Scope::ClientWrite) {
        if let Some(v) = body.user {
            doc.insert("user", id);
        }
        if let Some(v) = body.locked {
            doc.insert("locked", v);
        }
    }
    if let Some(v) = body.name {
        doc.insert("name", v);
    }
    if let Some(v) = body.scope {
        doc.insert("scope", v);
    }
    if doc.is_empty() {
        return Err(QueryError::InvalidBody.into());
    }

    let user = if !claims.scope.contains(&Scope::ClientWrite) {
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
    if !claims.scope.contains(&Scope::ClientWrite) {
        return Err(AuthError::InsufficientPermission.into());
    }

    clients.delete(id).await?;

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
    client_id: String,
    secret: Secret<CLIENT_SECRET_LENGTH>,
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
    State(password): State<Password>,
    Json(body): Json<CredentialsRequest>,
) -> ServiceResult<Response<CredentialsResponse>> {
    let client = if claims.scope.contains(&Scope::ClientWrite) {
        clients.get_by_id(id).await?
    } else {
        clients.get_by_id_and_user(id, claims.sub).await?
    };

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

    let client_id = crypto::gen::generate_id::<CLIENT_ID_LENGTH>();
    let client_secret = crypto::gen::generate_secret();

    let doc = OauthDocument {
        id: client_id.clone(),
        secret: password.hash(client_secret)?,
        last_seen: Default::default(),
        expires,
        issued: Utc::now(),
    };

    clients.set_oauth(id, doc).await?;

    let response = CredentialsResponse {
        client_id,
        secret: client_secret.into(),
        expires,
    };

    Ok(Response::with_status(StatusCode::CREATED, response))
}
