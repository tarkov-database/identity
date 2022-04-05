use crate::{
    action::send_verification_mail,
    authentication::{
        password::{self, Hibp},
        token::TokenConfig,
        AuthenticationError,
    },
    database::Database,
    error::QueryError,
    extract::{Query, SizedJson, TokenData},
    mail,
    model::{List, ListOptions, Response, Status},
    session::{self, SessionClaims},
    utils, GlobalConfig,
};

use super::{Connection, Role, SessionDocument, UserDocument, UserError};

use axum::extract::{Extension, Path};
use chrono::{serde::ts_seconds, DateTime, Utc};
use hyper::StatusCode;
use mongodb::bson::{doc, oid::ObjectId, to_bson, to_document, Document};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub roles: Vec<Role>,
    pub verified: bool,
    pub connections: Vec<Connection>,
    pub last_sessions: Vec<SessionResponse>,
    #[serde(with = "ts_seconds")]
    pub last_modified: DateTime<Utc>,
}

impl From<UserDocument> for UserResponse {
    fn from(doc: UserDocument) -> Self {
        Self {
            id: doc.id.to_hex(),
            email: doc.email,
            verified: doc.verified,
            roles: doc.roles,
            connections: doc.connections,
            last_sessions: doc
                .last_sessions
                .into_iter()
                .map(SessionResponse::from)
                .collect(),
            last_modified: doc.last_modified,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    #[serde(with = "ts_seconds")]
    pub date: DateTime<Utc>,
}

impl From<SessionDocument> for SessionResponse {
    fn from(doc: SessionDocument) -> Self {
        Self { date: doc.date }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Filter {
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<Role>,
}

pub async fn list(
    TokenData(claims): TokenData<SessionClaims>,
    Query(filter): Query<Filter>,
    Query(opts): Query<ListOptions>,
    Extension(db): Extension<Database>,
) -> crate::Result<Response<List<UserResponse>>> {
    let filter = if !claims.scope.contains(&session::Scope::UserRead) {
        doc! { "_id": ObjectId::parse_str(&claims.sub).unwrap() }
    } else {
        to_document(&filter).unwrap()
    };

    let (users, total) = db.get_users(filter, opts).await?;

    let list = List::new(total, users);

    Ok(Response::new(list))
}

pub async fn get_by_id(
    Path(id): Path<String>,
    TokenData(claims): TokenData<SessionClaims>,
    Extension(db): Extension<Database>,
) -> crate::Result<Response<UserResponse>> {
    if !claims.scope.contains(&session::Scope::UserRead) && claims.sub != id {
        return Err(AuthenticationError::InsufficientPermission.into());
    }

    let id = ObjectId::parse_str(&id).map_err(|_| UserError::InvalidId)?;

    let user = db.get_user(doc! { "_id": id }).await?;

    Ok(Response::new(user.into()))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    email: String,
    password: String,
    #[serde(default)]
    roles: Vec<Role>,
}

pub async fn create(
    TokenData(claims): TokenData<SessionClaims>,
    SizedJson(body): SizedJson<CreateRequest>,
    Extension(db): Extension<Database>,
    Extension(global): Extension<GlobalConfig>,
    Extension(hibp): Extension<Hibp>,
    Extension(mail): Extension<mail::Client>,
    Extension(config): Extension<TokenConfig>,
) -> crate::Result<Response<UserResponse>> {
    if !claims.scope.contains(&session::Scope::UserWrite) {
        return Err(AuthenticationError::InsufficientPermission.into());
    }

    let domain = utils::get_email_domain(&body.email).ok_or(UserError::InvalidAddr)?;

    if !global.is_allowed_domain(domain) {
        return Err(UserError::DomainNotAllowed.into());
    }

    if db.get_user(doc! { "email": &body.email }).await.is_ok() {
        return Err(UserError::AlreadyExists.into());
    }

    let password_hash = password::validate_and_hash(&body.password)?;

    if global.hibp_check_enabled {
        hibp.check_password(&body.password).await?;
    }

    let user = UserDocument {
        id: ObjectId::new(),
        email: body.email,
        password: Some(password_hash),
        roles: body.roles,
        last_modified: Utc::now(),
        ..Default::default()
    };

    db.insert_user(&user).await?;

    send_verification_mail(&user.email, &user.id.to_hex(), mail, config).await?;

    Ok(Response::with_status(StatusCode::CREATED, user.into()))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRequest {
    email: Option<String>,
    password: Option<String>,
    verified: Option<bool>,
    roles: Option<Vec<Role>>,
}

pub async fn update(
    Path(id): Path<String>,
    TokenData(claims): TokenData<SessionClaims>,
    SizedJson(body): SizedJson<UpdateRequest>,
    Extension(db): Extension<Database>,
    Extension(mail): Extension<mail::Client>,
    Extension(config): Extension<TokenConfig>,
) -> crate::Result<Response<UserResponse>> {
    if !claims.scope.contains(&session::Scope::UserWrite) && claims.sub != id {
        return Err(AuthenticationError::InsufficientPermission.into());
    }

    let id = ObjectId::parse_str(&id).map_err(|_| UserError::InvalidId)?;

    let mut doc = Document::new();
    if let Some(v) = body.email {
        send_verification_mail(&v, &id.to_hex(), mail, config).await?;
        doc.insert("verified", false);
        doc.insert("email", v);
    }
    if let Some(v) = body.password {
        let hash = password::validate_and_hash(&v)?;
        doc.insert("password", hash);
    }

    if claims.scope.contains(&session::Scope::UserWrite) {
        if let Some(v) = body.verified {
            doc.insert("verified", v);
        }
        if let Some(v) = body.roles {
            doc.insert("roles", to_bson(&v).unwrap());
        }
    }

    if doc.is_empty() {
        return Err(QueryError::InvalidBody.into());
    }

    let doc = db.update_user_by_id(id, doc).await?;

    Ok(Response::new(doc.into()))
}

pub async fn delete(
    Path(id): Path<String>,
    TokenData(claims): TokenData<SessionClaims>,
    Extension(db): Extension<Database>,
) -> crate::Result<Status> {
    if !claims.scope.contains(&session::Scope::UserWrite) {
        return Err(AuthenticationError::InsufficientPermission.into());
    }

    let id = ObjectId::parse_str(&id).map_err(|_| UserError::InvalidId)?;

    db.delete_user(id).await?;

    Ok(Status::new(StatusCode::OK, "user deleted"))
}
