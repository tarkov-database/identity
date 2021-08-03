use crate::{
    authentication::AuthenticationError,
    database::Database,
    error::{Error, QueryError},
    model::{List, ListOptions, Status},
    session::{self, SessionClaims},
    user::UserError,
};

use super::{ClientDocument, ClientError};

use chrono::{serde::ts_seconds, DateTime, NaiveDateTime, Utc};
use mongodb::bson::{doc, oid::ObjectId, to_document, Document};
use serde::{Deserialize, Serialize};
use warp::{http::StatusCode, reply, Rejection, Reply};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientResponse {
    pub id: String,
    pub user: String,
    pub service: String,
    pub name: String,
    pub scope: Vec<String>,
    pub unlocked: bool,
    #[serde(with = "ts_seconds")]
    pub last_issued: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub last_modified: DateTime<Utc>,
}

impl From<ClientDocument> for ClientResponse {
    fn from(doc: ClientDocument) -> Self {
        Self {
            id: doc.id.to_hex(),
            user: doc.user.to_hex(),
            service: doc.service.to_hex(),
            name: doc.name,
            scope: doc.scope,
            unlocked: doc.unlocked,
            last_issued: doc.last_issued,
            last_modified: doc.last_modified,
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
    claims: SessionClaims,
    filter: Filter,
    opts: ListOptions,
    db: Database,
) -> std::result::Result<reply::Response, Rejection> {
    let user = if !claims.scope.contains(&session::Scope::ClientRead) {
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
    let list: List<ClientResponse> =
        List::new(total, clients.into_iter().map(|d| d.into()).collect());

    Ok(list.into())
}

pub async fn get_by_id(
    id: String,
    claims: SessionClaims,
    db: Database,
) -> std::result::Result<reply::Response, Rejection> {
    let id = match ObjectId::parse_str(&id) {
        Ok(v) => v,
        Err(_) => return Err(Error::from(ClientError::InvalidId).into()),
    };

    let mut filter = doc! { "_id": id };
    if !claims.scope.contains(&session::Scope::ClientRead) {
        let id = ObjectId::parse_str(&claims.sub).unwrap();
        filter.insert("user", id);
    }

    let client = db.get_client(filter).await?;

    Ok(
        reply::with_status(reply::json(&ClientResponse::from(client)), StatusCode::OK)
            .into_response(),
    )
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
    claims: SessionClaims,
    body: CreateRequest,
    db: Database,
) -> std::result::Result<reply::Response, Rejection> {
    let user_id = if let Some(id) = body.user {
        if !claims.scope.contains(&session::Scope::ClientWrite) && claims.sub != id {
            return Err(Error::from(AuthenticationError::InsufficientPermission).into());
        }
        match ObjectId::parse_str(&id) {
            Ok(v) => v,
            Err(_) => return Err(Error::from(UserError::InvalidId).into()),
        }
    } else {
        ObjectId::parse_str(&claims.sub).unwrap()
    };

    let svc_id = match ObjectId::parse_str(&body.service) {
        Ok(v) => v,
        Err(_) => return Err(Error::from(UserError::InvalidId).into()),
    };

    let svc = db.get_service(doc! { "_id": svc_id }).await?;

    let client = ClientDocument {
        id: ObjectId::new(),
        user: user_id,
        name: body.name,
        service: svc_id,
        scope: svc.scope_default,
        unlocked: false,
        last_issued: DateTime::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc),
        last_modified: Utc::now(),
    };

    db.insert_client(&client).await?;

    Ok(reply::with_status(
        reply::json(&ClientResponse::from(client)),
        StatusCode::CREATED,
    )
    .into_response())
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRequest {
    user: Option<String>,
    name: Option<String>,
    scope: Option<Vec<String>>,
    unlocked: Option<bool>,
}

pub async fn update(
    id: String,
    claims: SessionClaims,
    body: UpdateRequest,
    db: Database,
) -> std::result::Result<reply::Response, Rejection> {
    let id = match ObjectId::parse_str(&id) {
        Ok(v) => v,
        Err(_) => return Err(Error::from(ClientError::InvalidId).into()),
    };

    let mut doc = Document::new();
    if claims.scope.contains(&session::Scope::ClientWrite) {
        if let Some(v) = body.user {
            let id = match ObjectId::parse_str(&v) {
                Ok(v) => v,
                Err(_) => return Err(Error::from(UserError::InvalidId).into()),
            };
            doc.insert("user", id);
        }
        if let Some(v) = body.unlocked {
            doc.insert("unlocked", v);
        }
    }
    if let Some(v) = body.name {
        doc.insert("name", v);
    }
    if let Some(v) = body.scope {
        doc.insert("scope", v);
    }
    if doc.is_empty() {
        return Err(Error::from(QueryError::InvalidBody).into());
    }

    let user = if !claims.scope.contains(&session::Scope::ClientWrite) {
        Some(ObjectId::parse_str(&claims.sub).unwrap())
    } else {
        None
    };

    let doc = db.update_client(id, user, doc).await?;

    Ok(reply::with_status(reply::json(&ClientResponse::from(doc)), StatusCode::OK).into_response())
}

pub async fn delete(
    id: String,
    claims: SessionClaims,
    db: Database,
) -> std::result::Result<reply::Response, Rejection> {
    if !claims.scope.contains(&session::Scope::ClientWrite) {
        return Err(Error::from(AuthenticationError::InsufficientPermission).into());
    }

    let id = match ObjectId::parse_str(&id) {
        Ok(v) => v,
        Err(_) => return Err(Error::from(ClientError::InvalidId).into()),
    };

    db.delete_client(id).await?;

    Ok(Status::new(StatusCode::OK, "client deleted").into())
}
