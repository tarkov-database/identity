use crate::{
    authentication::AuthenticationError,
    database::Database,
    error::{Error, QueryError},
    model::{List, ListOptions, Status},
    session::{self, SessionClaims},
    utils::crypto::Aead256,
};

use super::{ServiceDocument, ServiceError};

use chrono::{serde::ts_seconds, DateTime, Utc};
use mongodb::bson::{doc, oid::ObjectId, to_document, Document};
use serde::{Deserialize, Serialize};
use warp::{http::StatusCode, reply, Rejection, Reply};

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
    filter: Filter,
    opts: ListOptions,
    db: Database,
) -> std::result::Result<reply::Response, Rejection> {
    if !claims.scope.contains(&session::Scope::ServiceRead) {
        return Err(Error::from(AuthenticationError::InsufficientPermission).into());
    }

    let (services, total) = db.get_services(to_document(&filter).unwrap(), opts).await?;
    let list: List<ServiceResponse> =
        List::new(total, services.into_iter().map(|d| d.into()).collect());

    Ok(list.into())
}

pub async fn get_by_id(
    id: String,
    claims: SessionClaims,
    db: Database,
) -> std::result::Result<reply::Response, Rejection> {
    if !claims.scope.contains(&session::Scope::ServiceRead) {
        return Err(Error::from(AuthenticationError::InsufficientPermission).into());
    }

    let id = match ObjectId::parse_str(&id) {
        Ok(v) => v,
        Err(_) => return Err(Error::from(ServiceError::InvalidId).into()),
    };

    let service = db.get_service(doc! { "_id": id }).await?;

    Ok(
        reply::with_status(reply::json(&ServiceResponse::from(service)), StatusCode::OK)
            .into_response(),
    )
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
    body: CreateRequest,
    db: Database,
    enc: Aead256,
) -> std::result::Result<reply::Response, Rejection> {
    if !claims.scope.contains(&session::Scope::ServiceWrite) {
        return Err(Error::from(AuthenticationError::InsufficientPermission).into());
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

    Ok(reply::with_status(
        reply::json(&ServiceResponse::from(service)),
        StatusCode::CREATED,
    )
    .into_response())
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
    id: String,
    claims: SessionClaims,
    body: UpdateRequest,
    db: Database,
    enc: Aead256,
) -> std::result::Result<reply::Response, Rejection> {
    if !claims.scope.contains(&session::Scope::ServiceWrite) {
        return Err(Error::from(AuthenticationError::InsufficientPermission).into());
    }

    let id = match ObjectId::parse_str(&id) {
        Ok(v) => v,
        Err(_) => return Err(Error::from(ServiceError::InvalidId).into()),
    };

    let svc = db.get_service(doc! { "_id": id }).await?;

    if let Some(ref def) = body.scope_default {
        if let Some(ref scope) = body.scope {
            if !def.iter().all(|s| scope.contains(s)) {
                return Err(Error::from(ServiceError::UndefinedScope).into());
            }
        } else if !def.iter().all(|s| svc.scope.contains(s)) {
            return Err(Error::from(ServiceError::UndefinedScope).into());
        }
    } else if let Some(ref scope) = body.scope {
        if svc.scope_default.iter().all(|s| scope.contains(s)) {
            return Err(Error::from(ServiceError::UndefinedScope).into());
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
        return Err(Error::from(QueryError::InvalidBody).into());
    }

    let doc = db.update_service(id, doc).await?;

    Ok(
        reply::with_status(reply::json(&ServiceResponse::from(doc)), StatusCode::OK)
            .into_response(),
    )
}

pub async fn delete(
    id: String,
    claims: SessionClaims,
    db: Database,
) -> std::result::Result<reply::Response, Rejection> {
    if !claims.scope.contains(&session::Scope::ServiceWrite) {
        return Err(Error::from(AuthenticationError::InsufficientPermission).into());
    }

    let id = match ObjectId::parse_str(&id) {
        Ok(v) => v,
        Err(_) => return Err(Error::from(ServiceError::InvalidId).into()),
    };

    db.delete_service(id).await?;

    Ok(Status::new(StatusCode::OK, "service deleted").into())
}
