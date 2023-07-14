use crate::{
    auth::AuthenticationError,
    database::Collection,
    error::QueryError,
    extract::{Json, Query, TokenData},
    model::{List, ListOptions, Response, Status},
    token::{AccessClaims, Scope},
};

use super::{model::ServiceDocument, ServiceError};

use axum::extract::{Path, State};
use chrono::{serde::ts_seconds, DateTime, Utc};
use hyper::StatusCode;
use mongodb::bson::{self, doc, oid::ObjectId, Document};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceResponse {
    pub id: String,
    pub name: String,
    pub audience: Vec<String>,
    pub scope: Vec<String>,
    pub default_scope: Vec<String>,
    #[serde(with = "ts_seconds")]
    pub last_modified: DateTime<Utc>,
}

impl From<ServiceDocument> for ServiceResponse {
    fn from(doc: ServiceDocument) -> Self {
        Self {
            id: doc.id.to_hex(),
            name: doc.name,
            audience: doc.audience,
            scope: doc.scope,
            default_scope: doc.scope_default,
            last_modified: doc.last_modified,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Filter {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    audience: Option<String>,
}

impl Into<bson::Document> for Filter {
    fn into(self) -> bson::Document {
        bson::to_document(&self).unwrap()
    }
}

pub async fn list(
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    Query(filter): Query<Filter>,
    Query(opts): Query<ListOptions>,
    State(services): State<Collection<ServiceDocument>>,
) -> crate::Result<Response<List<ServiceResponse>>> {
    if !claims.scope.contains(&Scope::ServiceRead) {
        return Err(AuthenticationError::InsufficientPermission.into());
    }

    let (services, total) = services
        .get_all(Some(filter.into()), Some(opts.into()))
        .await?;
    let list = List::new(total, services);

    Ok(Response::new(list))
}

pub async fn get_by_id(
    Path(id): Path<ObjectId>,
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    State(services): State<Collection<ServiceDocument>>,
) -> crate::Result<Response<ServiceResponse>> {
    if !claims.scope.contains(&Scope::ServiceRead) {
        return Err(AuthenticationError::InsufficientPermission.into());
    }

    let service = services.get_by_id(id).await?;

    Ok(Response::with_status(StatusCode::OK, service.into()))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    name: String,
    audience: Vec<String>,
    scope: Vec<String>,
    scope_default: Vec<String>,
}

pub async fn create(
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    State(services): State<Collection<ServiceDocument>>,
    Json(body): Json<CreateRequest>,
) -> crate::Result<Response<ServiceResponse>> {
    if !claims.scope.contains(&Scope::ServiceWrite) {
        return Err(AuthenticationError::InsufficientPermission.into());
    }

    let service = ServiceDocument {
        id: ObjectId::new(),
        name: body.name,
        audience: body.audience,
        scope: body.scope,
        scope_default: body.scope_default,
        last_modified: Utc::now(),
        created: Utc::now(),
    };

    services.insert(&service).await?;

    Ok(Response::with_status(StatusCode::CREATED, service.into()))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRequest {
    name: Option<String>,
    audience: Option<String>,
    scope: Option<Vec<String>>,
    scope_default: Option<Vec<String>>,
}

pub async fn update(
    Path(id): Path<ObjectId>,
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    State(services): State<Collection<ServiceDocument>>,
    Json(body): Json<UpdateRequest>,
) -> crate::Result<Response<ServiceResponse>> {
    if !claims.scope.contains(&Scope::ServiceWrite) {
        return Err(AuthenticationError::InsufficientPermission.into());
    }

    let svc = services.get_by_id(id).await?;

    if let Some(ref def) = body.scope_default {
        if let Some(ref scope) = body.scope {
            if !def.iter().all(|s| scope.contains(s)) {
                return Err(ServiceError::UndefinedScope.into());
            }
        } else if !def.iter().all(|s| svc.scope.contains(s)) {
            return Err(ServiceError::UndefinedScope.into());
        }
    } else if let Some(ref scope) = body.scope {
        if svc.scope_default.iter().all(|s| scope.contains(s)) {
            return Err(ServiceError::UndefinedScope.into());
        }
    }

    let mut doc = Document::new();
    if let Some(v) = body.name {
        doc.insert("name", v);
    }
    if let Some(v) = body.audience {
        doc.insert("audience", v);
    }
    if let Some(v) = body.scope {
        doc.insert("scope", v);
    }
    if let Some(v) = body.scope_default {
        doc.insert("scopeDefault", v);
    }
    if doc.is_empty() {
        return Err(QueryError::InvalidBody.into());
    }

    let doc = services.update(id, doc).await?;

    Ok(Response::with_status(StatusCode::OK, doc.into()))
}

pub async fn delete(
    Path(id): Path<ObjectId>,
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    State(services): State<Collection<ServiceDocument>>,
) -> crate::Result<Status> {
    if !claims.scope.contains(&Scope::ServiceWrite) {
        return Err(AuthenticationError::InsufficientPermission.into());
    }

    services.delete(id).await?;

    Ok(Status::new(StatusCode::OK, "service deleted"))
}
