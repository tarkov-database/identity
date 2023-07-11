use crate::{
    auth::{token::sign::TokenSigner, AuthenticationError},
    database::Database,
    error::QueryError,
    extract::{Json, Query, TokenData},
    model::{List, ListOptions, Response, Status},
    service::ServiceError,
    token::{AccessClaims, Scope},
    user::UserError,
};

use super::{ClientClaims, ClientDocument, ClientError, TokenDocument};

use axum::extract::{Path, State};
use chrono::{serde::ts_seconds, DateTime, Duration, Utc};
use hyper::StatusCode;
use mongodb::bson::{doc, oid::ObjectId, to_document, Document};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientResponse {
    pub id: String,
    pub user: String,
    pub service: String,
    pub name: String,
    pub scope: Vec<String>,
    pub locked: bool,
    pub token: Option<ClientTokenResponse>,
    #[serde(with = "ts_seconds")]
    pub last_used: DateTime<Utc>,
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
            token: doc.token.map(ClientTokenResponse::from),
            last_used: doc.last_used,
            last_modified: doc.last_modified,
            created: doc.created,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientTokenResponse {
    pub id: Uuid,
    #[serde(with = "ts_seconds")]
    pub expires: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub issued: DateTime<Utc>,
}

impl From<TokenDocument> for ClientTokenResponse {
    fn from(doc: TokenDocument) -> Self {
        Self {
            id: doc.id.into(),
            expires: doc.expires,
            issued: doc.issued,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Filter {
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approved: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
}

pub async fn list(
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    Query(filter): Query<Filter>,
    Query(opts): Query<ListOptions>,
    State(db): State<Database>,
) -> crate::Result<Response<List<ClientResponse>>> {
    let user = if !claims.scope.contains(&Scope::ClientRead) {
        Some(&claims.sub)
    } else {
        filter.user.as_ref()
    };

    let mut f = to_document(&filter).unwrap();
    if let Some(id) = user {
        f.insert("user", ObjectId::parse_str(id).unwrap());
    }
    if let Some(id) = filter.service {
        f.insert("service", ObjectId::parse_str(id).unwrap());
    }

    let (clients, total) = db.get_clients(f, opts).await?;
    let list = List::new(total, clients);

    Ok(Response::new(list))
}

pub async fn get_by_id(
    Path(id): Path<String>,
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    State(db): State<Database>,
) -> crate::Result<Response<ClientResponse>> {
    let id = ObjectId::parse_str(&id).map_err(|_| ClientError::InvalidId)?;

    let mut filter = doc! { "_id": id };
    if !claims.scope.contains(&Scope::ClientRead) {
        let id = ObjectId::parse_str(&claims.sub).unwrap();
        filter.insert("user", id);
    }

    let client = db.get_client(filter).await?;

    Ok(Response::with_status(StatusCode::OK, client.into()))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    user: Option<String>,
    name: String,
    service: String,
    scope: Option<Vec<String>>,
}

pub async fn create(
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    State(db): State<Database>,
    Json(body): Json<CreateRequest>,
) -> crate::Result<Response<ClientResponse>> {
    let user_id = if let Some(id) = body.user {
        if !claims.scope.contains(&Scope::ClientWrite) && claims.sub != id {
            return Err(AuthenticationError::InsufficientPermission.into());
        }
        ObjectId::parse_str(&id).map_err(|_| UserError::InvalidId)?
    } else {
        ObjectId::parse_str(&claims.sub).unwrap()
    };

    let svc_id = ObjectId::parse_str(&body.service).map_err(|_| ServiceError::InvalidId)?;

    let svc = db.get_service(doc! { "_id": svc_id }).await?;

    let client = ClientDocument {
        id: ObjectId::new(),
        user: user_id,
        name: body.name,
        service: svc_id,
        scope: svc.scope_default,
        locked: false,
        token: None,
        last_used: Default::default(),
        last_modified: Utc::now(),
        created: Utc::now(),
    };

    db.insert_client(&client).await?;

    Ok(Response::with_status(StatusCode::CREATED, client.into()))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRequest {
    user: Option<String>,
    name: Option<String>,
    scope: Option<Vec<String>>,
    locked: Option<bool>,
}

pub async fn update(
    Path(id): Path<String>,
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    State(db): State<Database>,
    Json(body): Json<UpdateRequest>,
) -> crate::Result<Response<ClientResponse>> {
    let id = ObjectId::parse_str(&id).map_err(|_| ClientError::InvalidId)?;

    let mut doc = Document::new();
    if claims.scope.contains(&Scope::ClientWrite) {
        if let Some(v) = body.user {
            let id = ObjectId::parse_str(&v).map_err(|_| UserError::InvalidId)?;
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
        Some(ObjectId::parse_str(&claims.sub).unwrap())
    } else {
        None
    };

    let doc = db.update_client(id, user, doc).await?;

    Ok(Response::with_status(StatusCode::OK, doc.into()))
}

pub async fn delete(
    Path(id): Path<String>,
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    State(db): State<Database>,
) -> crate::Result<Status> {
    if !claims.scope.contains(&Scope::ClientWrite) {
        return Err(AuthenticationError::InsufficientPermission.into());
    }

    let id = ObjectId::parse_str(&id).map_err(|_| ClientError::InvalidId)?;

    db.delete_client(id).await?;

    Ok(Status::new(StatusCode::OK, "client deleted"))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenRequest {
    /// Period of validity for the token in seconds.
    #[serde(default)]
    validity: u64,
}

impl Default for TokenRequest {
    fn default() -> Self {
        Self {
            validity: Duration::days(365).num_seconds() as u64,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenResponse {
    token: String,
    #[serde(with = "ts_seconds")]
    expires: DateTime<Utc>,
}

pub async fn create_token(
    Path(id): Path<String>,
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    State(db): State<Database>,
    State(signer): State<TokenSigner>,
    Json(body): Json<TokenRequest>,
) -> crate::Result<Response<TokenResponse>> {
    let id = ObjectId::parse_str(&id).map_err(|_| ClientError::InvalidId)?;

    let client = db.get_client(doc! { "_id": id }).await?;
    if client.locked {
        return Err(ClientError::Locked)?;
    }

    if !claims.scope.contains(&Scope::ClientWrite) && claims.sub != client.user.to_hex() {
        return Err(AuthenticationError::InsufficientPermission)?;
    }

    let validity = Duration::seconds(body.validity as i64);

    if validity > Duration::days(365) || validity < Duration::seconds(60) {
        return Err(ClientError::InvalidExpiration)?;
    }

    let expires = Utc::now() + validity;

    let doc = TokenDocument::new(expires);
    let claims = ClientClaims::new(doc.id, &client.id.to_hex(), &client.user.to_hex(), expires);

    let token = signer.sign(&claims).await?;

    db.set_client_token(id, doc).await?;

    let response = TokenResponse {
        token,
        expires: claims.exp,
    };

    Ok(Response::with_status(StatusCode::CREATED, response))
}
