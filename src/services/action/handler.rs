use crate::{
    auth::{password::Password, token::sign::TokenSigner},
    database::Collection,
    mail,
    services::extract::{Json, Query, TokenData},
    services::model::Status,
    services::{
        user::{
            model::{Role, UserDocument},
            UserError,
        },
        ServiceResult,
    },
    utils, GlobalConfig,
};

use super::{send_reset_mail, send_verification_mail, ActionClaims, ActionError, Reset, Verify};

use axum::extract::State;
use chrono::Utc;
use hyper::StatusCode;
use mongodb::bson::{doc, oid::ObjectId};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    email: String,
    password: String,
}

pub async fn register(
    State(users): State<Collection<UserDocument>>,
    State(global): State<GlobalConfig>,
    State(password): State<Password>,
    State(mail): State<mail::Client>,
    State(signer): State<TokenSigner>,
    Json(body): Json<RegisterRequest>,
) -> ServiceResult<Status> {
    let domain = utils::get_email_domain(&body.email).ok_or(UserError::InvalidAddr)?;

    if !global.is_allowed_domain(domain) {
        return Err(UserError::DomainNotAllowed)?;
    }

    if users.get_by_email(&body.email).await.is_ok() {
        return Err(UserError::AlreadyExists)?;
    }

    let password_hash = password.validate_and_hash(&body.password).await?;

    let roles = if global.is_editor_address(&body.email) {
        vec![Role::UserEditor]
    } else {
        Default::default()
    };

    let user = UserDocument {
        id: ObjectId::new(),
        email: body.email,
        password: Some(password_hash),
        roles,
        last_modified: Utc::now(),
        ..Default::default()
    };

    users.insert(&user).await?;

    send_verification_mail(user.email, user.id, mail, signer).await?;

    Ok(Status::new(StatusCode::CREATED, "user registered"))
}

pub async fn verify_email(
    TokenData(claims): TokenData<ActionClaims<Verify>>,
    State(users): State<Collection<UserDocument>>,
) -> ServiceResult<Status> {
    let addr = claims.email.ok_or(ActionError::InvalidToken)?;

    let user = users.get_by_id(claims.sub).await?;

    if user.email != addr {
        return Err(ActionError::InvalidToken)?;
    }
    if user.verified {
        return Err(ActionError::AlreadyVerified)?;
    }

    users.update(claims.sub, doc! { "verified": true }).await?;

    Ok(Status::new(StatusCode::OK, "account verified"))
}

#[derive(Debug, Deserialize)]
pub struct ResetOptions {
    email: String,
}

pub async fn request_reset(
    Query(opts): Query<ResetOptions>,
    State(users): State<Collection<UserDocument>>,
    State(mail): State<mail::Client>,
    State(signer): State<TokenSigner>,
) -> ServiceResult<Status> {
    let user = users.get_by_email(&opts.email).await?;

    if !user.verified {
        return Err(ActionError::NotVerified)?;
    }

    send_reset_mail(user.email, user.id, mail, signer).await?;

    Ok(Status::new(StatusCode::OK, "reset email sent"))
}

#[derive(Debug, Deserialize)]
pub struct ResetRequest {
    password: String,
}

pub async fn reset_password(
    TokenData(claims): TokenData<ActionClaims<Reset>>,
    State(users): State<Collection<UserDocument>>,
    State(password): State<Password>,
    Json(body): Json<ResetRequest>,
) -> ServiceResult<Status> {
    let password_hash = password.validate_and_hash(&body.password).await?;

    users
        .update(claims.sub, doc! { "password": password_hash })
        .await?;

    Ok(Status::new(StatusCode::OK, "new password set"))
}
