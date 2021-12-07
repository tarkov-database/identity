use crate::{
    authentication::AuthenticationError,
    database::Database,
    error::QueryError,
    model::{List, ListOptions, Response, Status},
    session::{self, SessionClaims},
    utils::crypto::Aead256,
};

use super::{ServiceDocument, ServiceError};

use axum::{
    extract::{Extension, Path, Query},
    Json,
};
use chrono::{serde::ts_seconds, DateTime, Utc};
use hyper::StatusCode;
use mongodb::bson::{doc, oid::ObjectId, to_document, Document};
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

pub async fn list(
    claims: SessionClaims,
    Query(filter): Query<Filter>,
    Query(opts): Query<ListOptions>,
    Extension(db): Extension<Database>,
) -> crate::Result<Response<List<ServiceResponse>>> {
    if !claims.scope.contains(&session::Scope::ServiceRead) {
        return Err(AuthenticationError::InsufficientPermission.into());
    }

    let (services, total) = db.get_services(to_document(&filter).unwrap(), opts).await?;
    let list = List::new(total, services);

    Ok(Response::new(list))
}

pub async fn get_by_id(
    Path(id): Path<String>,
    claims: SessionClaims,
    Extension(db): Extension<Database>,
) -> crate::Result<Response<ServiceResponse>> {
    if !claims.scope.contains(&session::Scope::ServiceRead) {
        return Err(AuthenticationError::InsufficientPermission.into());
    }

    let id = match ObjectId::parse_str(&id) {
        Ok(v) => v,
        Err(_) => return Err(ServiceError::InvalidId.into()),
    };

    let service = db.get_service(doc! { "_id": id }).await?;

    Ok(Response::with_status(StatusCode::OK, service.into()))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    name: String,
    audience: Vec<String>,
    scope: Vec<String>,
    scope_default: Vec<String>,
    secret: Option<String>,
}

pub async fn create(
    claims: SessionClaims,
    Json(body): Json<CreateRequest>,
    Extension(db): Extension<Database>,
    Extension(enc): Extension<Aead256>,
) -> crate::Result<Response<ServiceResponse>> {
    if !claims.scope.contains(&session::Scope::ServiceWrite) {
        return Err(AuthenticationError::InsufficientPermission.into());
    }

    let secret = if let Some(s) = body.secret {
        base64::encode_config(enc.encrypt(s), base64::STANDARD).into()
    } else {
        None
    };

    let service = ServiceDocument {
        id: ObjectId::new(),
        name: body.name,
        audience: body.audience,
        scope: body.scope,
        scope_default: body.scope_default,
        secret,
        last_modified: Utc::now(),
    };

    db.insert_service(&service).await?;

    Ok(Response::with_status(StatusCode::CREATED, service.into()))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRequest {
    name: Option<String>,
    audience: Option<String>,
    scope: Option<Vec<String>>,
    scope_default: Option<Vec<String>>,
    secret: Option<String>,
}

pub async fn update(
    Path(id): Path<String>,
    claims: SessionClaims,
    Json(body): Json<UpdateRequest>,
    Extension(db): Extension<Database>,
    Extension(enc): Extension<Aead256>,
) -> crate::Result<Response<ServiceResponse>> {
    if !claims.scope.contains(&session::Scope::ServiceWrite) {
        return Err(AuthenticationError::InsufficientPermission.into());
    }

    let id = match ObjectId::parse_str(&id) {
        Ok(v) => v,
        Err(_) => return Err(ServiceError::InvalidId.into()),
    };

    let svc = db.get_service(doc! { "_id": id }).await?;

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
    if let Some(s) = body.secret {
        let secret = base64::encode_config(enc.encrypt(s), base64::STANDARD);
        doc.insert("secret", secret);
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

    let doc = db.update_service(id, doc).await?;

    Ok(Response::with_status(StatusCode::OK, doc.into()))
}

pub async fn delete(
    Path(id): Path<String>,
    claims: SessionClaims,
    Extension(db): Extension<Database>,
) -> crate::Result<Status> {
    if !claims.scope.contains(&session::Scope::ServiceWrite) {
        return Err(AuthenticationError::InsufficientPermission.into());
    }

    let id = match ObjectId::parse_str(&id) {
        Ok(v) => v,
        Err(_) => return Err(ServiceError::InvalidId.into()),
    };

    db.delete_service(id).await?;

    Ok(Status::new(StatusCode::OK, "service deleted"))
}
