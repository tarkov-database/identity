use crate::{
    auth::{password::Password, token::sign::TokenSigner, AuthError},
    database::Collection,
    mail,
    services::{
        action::send_verification_mail,
        error::QueryError,
        extract::{Json, Query, TokenData},
        model::{EmailAddr, List, ListOptions, Response, Status},
        token::{AccessClaims, Scope},
        ServiceResult,
    },
    GlobalConfig,
};

use super::{
    model::{Connection, Role, SessionDocument, UserDocument},
    UserError,
};

use axum::extract::{Path, State};
use chrono::{serde::ts_seconds, DateTime, Utc};
use hyper::StatusCode;
use mongodb::bson::{
    doc, oid::ObjectId, serde_helpers::serialize_object_id_as_hex_string, to_bson, to_document,
    Document,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserResponse {
    #[serde(serialize_with = "serialize_object_id_as_hex_string")]
    pub id: ObjectId,
    pub email: EmailAddr,
    pub roles: Vec<Role>,
    pub verified: bool,
    pub can_login: bool,
    pub locked: bool,
    pub connections: Vec<Connection>,
    pub sessions: Vec<SessionResponse>,
    #[serde(with = "ts_seconds")]
    pub last_modified: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub created: DateTime<Utc>,
}

impl From<UserDocument> for UserResponse {
    fn from(doc: UserDocument) -> Self {
        Self {
            id: doc.id,
            email: doc.email,
            verified: doc.verified,
            can_login: doc.can_login,
            locked: doc.locked,
            roles: doc.roles,
            connections: doc.connections,
            sessions: doc
                .sessions
                .into_iter()
                .map(SessionResponse::from)
                .collect(),
            last_modified: doc.last_modified,
            created: doc.created,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    pub id: Uuid,
    #[serde(with = "ts_seconds")]
    pub last_seen: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub issued: DateTime<Utc>,
}

impl From<SessionDocument> for SessionResponse {
    fn from(doc: SessionDocument) -> Self {
        Self {
            id: doc.id.into(),
            last_seen: doc.last_seen,
            issued: doc.issued,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Filter {
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<EmailAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<Role>,
}

impl From<Filter> for mongodb::bson::Document {
    fn from(v: Filter) -> Self {
        to_document(&v).unwrap()
    }
}

pub async fn list(
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    Query(filter): Query<Filter>,
    Query(opts): Query<ListOptions>,
    State(users): State<Collection<UserDocument>>,
) -> ServiceResult<Response<List<UserResponse>>> {
    let filter = if !claims.scope.contains(&Scope::UserRead) {
        doc! { "_id": claims.sub }
    } else {
        filter.into()
    };

    let (users, total) = users.get_all(filter, Some(opts.into())).await?;

    let list = List::new(total, users);

    Ok(Response::new(list))
}

pub async fn get_by_id(
    Path(id): Path<ObjectId>,
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    State(users): State<Collection<UserDocument>>,
) -> ServiceResult<Response<UserResponse>> {
    if !claims.scope.contains(&Scope::UserRead) && claims.sub != id {
        return Err(AuthError::InsufficientPermission)?;
    }

    let user = users.get_by_id(id).await?;

    Ok(Response::new(user.into()))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    email: EmailAddr,
    password: String,
    #[serde(default)]
    roles: Vec<Role>,
}

pub async fn create(
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    State(global): State<GlobalConfig>,
    State(password): State<Password>,
    State(mail): State<mail::Client>,
    State(signer): State<TokenSigner>,
    State(users): State<Collection<UserDocument>>,
    Json(body): Json<CreateRequest>,
) -> ServiceResult<Response<UserResponse>> {
    if !claims.scope.contains(&Scope::UserWrite) {
        return Err(AuthError::InsufficientPermission)?;
    }

    if !global.is_allowed_domain(body.email.domain()) {
        return Err(UserError::DomainNotAllowed)?;
    }

    if users.get_by_email(&body.email).await.is_ok() {
        return Err(UserError::AlreadyExists)?;
    }

    let password_hash = password.validate_and_hash(&body.password).await?;

    let user = UserDocument {
        id: ObjectId::new(),
        email: body.email,
        password: Some(password_hash),
        roles: body.roles,
        can_login: false,
        verified: false,
        locked: false,
        connections: Default::default(),
        sessions: Default::default(),
        last_modified: Utc::now(),
        created: Utc::now(),
    };

    users.insert(&user).await?;

    send_verification_mail(user.email.clone(), user.id, mail, signer).await?;

    Ok(Response::with_status(StatusCode::CREATED, user.into()))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRequest {
    email: Option<EmailAddr>,
    password: Option<String>,
    verified: Option<bool>,
    roles: Option<Vec<Role>>,
}

pub async fn update(
    Path(id): Path<ObjectId>,
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    State(password): State<Password>,
    State(mail): State<mail::Client>,
    State(signer): State<TokenSigner>,
    State(users): State<Collection<UserDocument>>,
    Json(body): Json<UpdateRequest>,
) -> ServiceResult<Response<UserResponse>> {
    if !claims.scope.contains(&Scope::UserWrite) && claims.sub != id {
        return Err(AuthError::InsufficientPermission)?;
    }

    let mut doc = Document::new();
    if let Some(v) = body.email {
        send_verification_mail(v.clone(), id, mail, signer).await?;
        doc.insert("verified", false);
        doc.insert("email", v);
    }
    if let Some(v) = body.password {
        let hash = password.validate_and_hash(v).await?;
        doc.insert("password", hash);
    }

    if claims.scope.contains(&Scope::UserWrite) {
        if let Some(v) = body.verified {
            doc.insert("verified", v);
        }
        if let Some(v) = body.roles {
            doc.insert("roles", to_bson(&v).unwrap());
        }
    }

    if doc.is_empty() {
        return Err(QueryError::InvalidBody)?;
    }

    let doc = users.update(id, doc).await?;

    Ok(Response::new(doc.into()))
}

pub async fn delete(
    Path(id): Path<ObjectId>,
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    State(users): State<Collection<UserDocument>>,
) -> ServiceResult<Status> {
    if !claims.scope.contains(&Scope::UserWrite) {
        return Err(AuthError::InsufficientPermission)?;
    }

    users.delete(id).await?;

    Ok(Status::new(StatusCode::OK, "user deleted"))
}
