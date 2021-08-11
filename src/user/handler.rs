use crate::{
    action::send_verification_request,
    authentication::{
        password::{self, PasswordError},
        token::TokenConfig,
        AuthenticationError,
    },
    database::Database,
    error::{Error, QueryError},
    mail,
    model::{List, ListOptions, Status},
    session::{self, SessionClaims},
};

use super::{Role, UserDocument, UserError};

use chrono::{serde::ts_seconds, DateTime, NaiveDateTime, Utc};
use log::error;
use mongodb::bson::{doc, oid::ObjectId, to_bson, to_document, Document};
use serde::{Deserialize, Serialize};
use warp::{http::StatusCode, reply, Rejection, Reply};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct UserResponse {
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
    filter: Filter,
    opts: ListOptions,
    db: Database,
) -> std::result::Result<reply::Response, Rejection> {
    let filter = if !claims.scope.contains(&session::Scope::UserRead) {
        doc! { "_id": ObjectId::parse_str(&claims.sub).unwrap() }
    } else {
        to_document(&filter).unwrap()
    };

    let (users, total) = db.get_users(filter, opts).await?;

    let list: List<UserResponse> = List::new(total, users.into_iter().map(|d| d.into()).collect());

    Ok(list.into())
}

pub async fn get_by_id(
    id: String,
    claims: SessionClaims,
    db: Database,
) -> std::result::Result<reply::Response, Rejection> {
    if !claims.scope.contains(&session::Scope::UserRead) && claims.sub != id {
        return Err(Error::from(AuthenticationError::InsufficientPermission).into());
    }

    let id = match ObjectId::parse_str(&id) {
        Ok(v) => v,
        Err(_) => return Err(Error::from(UserError::InvalidId).into()),
    };

    let user = db.get_user(doc! { "_id": id }).await?;

    Ok(reply::with_status(reply::json(&UserResponse::from(user)), StatusCode::OK).into_response())
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
    body: CreateRequest,
    db: Database,
    mail: mail::Client,
    config: TokenConfig,
) -> std::result::Result<reply::Response, Rejection> {
    if db.get_user(doc! { "email": &body.email }).await.is_ok() {
        return Err(Error::from(UserError::AlreadyExists).into());
    }

    let password_hash = process_password(&body.password)?;

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

    send_verification_request(&user.email, &user.id.to_hex(), mail, config).await?;

    Ok(
        reply::with_status(reply::json(&UserResponse::from(user)), StatusCode::CREATED)
            .into_response(),
    )
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
    id: String,
    claims: SessionClaims,
    body: UpdateRequest,
    db: Database,
    mail: mail::Client,
    config: TokenConfig,
) -> std::result::Result<reply::Response, Rejection> {
    if !claims.scope.contains(&session::Scope::UserWrite) && claims.sub != id {
        return Err(Error::from(AuthenticationError::InsufficientPermission).into());
    }

    let id = match ObjectId::parse_str(&id) {
        Ok(v) => v,
        Err(_) => return Err(Error::from(UserError::InvalidId).into()),
    };

    let mut doc = Document::new();
    if let Some(v) = body.email {
        send_verification_request(&v, &id.to_hex(), mail, config).await?;
        doc.insert("verified", false);
        doc.insert("email", v);
    }
    if let Some(v) = body.password {
        let hash = process_password(&v)?;
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
        return Err(Error::from(QueryError::InvalidBody).into());
    }

    let doc = db.update_user(id, doc).await?;

    Ok(reply::with_status(reply::json(&UserResponse::from(doc)), StatusCode::OK).into_response())
}

pub async fn delete(
    id: String,
    claims: SessionClaims,
    db: Database,
) -> std::result::Result<reply::Response, Rejection> {
    if !claims.scope.contains(&session::Scope::UserWrite) {
        return Err(Error::from(AuthenticationError::InsufficientPermission).into());
    }

    let id = match ObjectId::parse_str(&id) {
        Ok(v) => v,
        Err(_) => return Err(Error::from(UserError::InvalidId).into()),
    };

    db.delete_user(id).await?;

    Ok(Status::new(StatusCode::OK, "user deleted").into())
}

fn process_password(password: &str) -> std::result::Result<String, Rejection> {
    if let Err(e) = password::validate_password(password) {
        return Err(Error::from(AuthenticationError::from(e)).into());
    }

    let password_hash =
        match password::hash_password(password) {
            Ok(h) => h,
            Err(e) => {
                error!("Error while hashing password: {:?}", e);
                return Err(Error::from(AuthenticationError::from(
                    PasswordError::InvalidPassword("bad input".to_string()),
                ))
                .into());
            }
        };

    Ok(password_hash)
}
