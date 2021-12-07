use crate::{
    action::send_verification_mail,
    authentication::{password, token::TokenConfig, AuthenticationError},
    database::Database,
    error::QueryError,
    mail,
    model::{List, ListOptions, Response, Status},
    session::{self, SessionClaims},
};

use super::{Role, UserDocument, UserError};

use axum::extract::{Extension, Json, Path, Query};
use chrono::{serde::ts_seconds, DateTime, NaiveDateTime, Utc};
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
    #[serde(with = "ts_seconds")]
    pub last_session: DateTime<Utc>,
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
            last_session: doc.last_session,
            last_modified: doc.last_modified,
        }
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
    claims: SessionClaims,
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
    claims: SessionClaims,
    Extension(db): Extension<Database>,
) -> crate::Result<Response<UserResponse>> {
    if !claims.scope.contains(&session::Scope::UserRead) && claims.sub != id {
        return Err(AuthenticationError::InsufficientPermission.into());
    }

    let id = match ObjectId::parse_str(&id) {
        Ok(v) => v,
        Err(_) => return Err(UserError::InvalidId.into()),
    };

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
    Json(body): Json<CreateRequest>,
    Extension(db): Extension<Database>,
    Extension(mail): Extension<mail::Client>,
    Extension(config): Extension<TokenConfig>,
) -> crate::Result<Response<UserResponse>> {
    if db.get_user(doc! { "email": &body.email }).await.is_ok() {
        return Err(UserError::AlreadyExists.into());
    }

    let password_hash = password::validate_and_hash(&body.password)?;

    let user = UserDocument {
        id: ObjectId::new(),
        email: body.email,
        password: password_hash,
        roles: body.roles,
        verified: false,
        can_login: true,
        last_session: DateTime::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc),
        last_modified: Utc::now(),
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
    claims: SessionClaims,
    Json(body): Json<UpdateRequest>,
    Extension(db): Extension<Database>,
    Extension(mail): Extension<mail::Client>,
    Extension(config): Extension<TokenConfig>,
) -> crate::Result<Response<UserResponse>> {
    if !claims.scope.contains(&session::Scope::UserWrite) && claims.sub != id {
        return Err(AuthenticationError::InsufficientPermission.into());
    }

    let id = match ObjectId::parse_str(&id) {
        Ok(v) => v,
        Err(_) => return Err(UserError::InvalidId.into()),
    };

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

    let doc = db.update_user(id, doc).await?;

    Ok(Response::new(doc.into()))
}

pub async fn delete(
    Path(id): Path<String>,
    claims: SessionClaims,
    Extension(db): Extension<Database>,
) -> crate::Result<Status> {
    if !claims.scope.contains(&session::Scope::UserWrite) {
        return Err(AuthenticationError::InsufficientPermission.into());
    }

    let id = match ObjectId::parse_str(&id) {
        Ok(v) => v,
        Err(_) => return Err(UserError::InvalidId.into()),
    };

    db.delete_user(id).await?;

    Ok(Status::new(StatusCode::OK, "user deleted"))
}
