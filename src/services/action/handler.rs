use crate::{
    auth::{
        password::{PasswordError, PasswordHasher, PasswordValidator},
        token::sign::TokenSigner,
    },
    crypto::Secret,
    database::Collection,
    mail,
    services::extract::{Json, Query, TokenData},
    services::{
        model::{EmailAddr, Status},
        token::{AccessClaims, Scope},
    },
    services::{
        user::{
            model::{Role, UserDocument},
            UserError,
        },
        ServiceResult,
    },
    GlobalConfig,
};

use super::{send_reset_mail, send_verification_mail, ActionClaims, ActionError, Reset, Verify};

use axum::extract::State;
use chrono::Utc;
use hyper::StatusCode;
use mongodb::bson::{doc, oid::ObjectId};
use serde::Deserialize;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    email: EmailAddr,
    password: Secret<String>,
}

impl std::fmt::Debug for RegisterRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterRequest")
            .field("email", &self.email)
            .field("password", &"********")
            .finish()
    }
}

pub async fn register(
    State(users): State<Collection<UserDocument>>,
    State(global): State<GlobalConfig>,
    State(validator): State<PasswordValidator>,
    State(hasher): State<PasswordHasher>,
    State(mail): State<mail::Client>,
    State(signer): State<TokenSigner>,
    Json(body): Json<RegisterRequest>,
) -> ServiceResult<Status> {
    if !global.is_allowed_domain(body.email.domain()) {
        return Err(UserError::DomainNotAllowed)?;
    }

    if users.get_by_email(&body.email).await.is_ok() {
        return Err(UserError::AlreadyExists)?;
    }

    validator.validate(&body.password).await?;
    let password_hash = hasher.hash(body.password).map_err(PasswordError::Hash)?;

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
        can_login: false,
        verified: false,
        locked: false,
        connections: Default::default(),
        sessions: Default::default(),
        tags: Default::default(),
        last_modified: Utc::now(),
        created: Utc::now(),
    };

    users.insert(&user).await?;

    send_verification_mail(user.email, user.id, mail, signer).await?;

    Ok(Status::new(StatusCode::CREATED, "user registered"))
}

#[derive(Debug, Deserialize)]
pub struct ChangeEmailRequest {
    email: EmailAddr,
}

pub async fn change_email(
    TokenData(claims): TokenData<AccessClaims<Scope>>,
    State(users): State<Collection<UserDocument>>,
    State(global): State<GlobalConfig>,
    State(mail): State<mail::Client>,
    State(signer): State<TokenSigner>,
    Json(body): Json<ChangeEmailRequest>,
) -> ServiceResult<Status> {
    if !global.is_allowed_domain(body.email.domain()) {
        return Err(UserError::DomainNotAllowed)?;
    }

    let user = users.get_by_id(claims.sub).await?;

    if user.email == body.email {
        return Err(ActionError::AlreadySet)?;
    }

    if users.get_by_email(&body.email).await.is_ok() {
        return Err(UserError::AlreadyExists)?;
    }

    send_verification_mail(body.email, user.id, mail, signer).await?;

    Ok(Status::new(StatusCode::OK, "verification email sent"))
}

pub async fn verify_email(
    TokenData(claims): TokenData<ActionClaims<Verify>>,
    State(users): State<Collection<UserDocument>>,
) -> ServiceResult<Status> {
    let addr = claims.email.ok_or(ActionError::InvalidToken)?;

    let user = users.get_by_id(claims.sub).await?;

    if user.email == addr {
        if user.verified {
            return Err(ActionError::AlreadyVerified)?;
        } else {
            users
                .update(claims.sub, doc! { "verified": true, "canLogin": true })
                .await?;
        }
    } else {
        users
            .update(claims.sub, doc! { "email": addr, "verified": true })
            .await?;
        // TODO: send email to old address
    }

    Ok(Status::new(StatusCode::OK, "email address verified"))
}

#[derive(Debug, Deserialize)]
pub struct ResetOptions {
    email: EmailAddr,
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

#[derive(Deserialize)]
pub struct ResetRequest {
    password: Secret<String>,
}

pub async fn reset_password(
    TokenData(claims): TokenData<ActionClaims<Reset>>,
    State(users): State<Collection<UserDocument>>,
    State(validator): State<PasswordValidator>,
    State(hasher): State<PasswordHasher>,
    Json(body): Json<ResetRequest>,
) -> ServiceResult<Status> {
    validator.validate(&body.password).await?;

    let password_hash = hasher.hash(body.password).map_err(PasswordError::Hash)?;

    users
        .update(claims.sub, doc! { "password": password_hash })
        .await?;

    Ok(Status::new(StatusCode::OK, "new password set"))
}
