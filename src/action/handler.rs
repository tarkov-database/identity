use crate::{
    authentication::{
        password::{self, Hibp},
        token::TokenConfig,
    },
    database::Database,
    extract::{Json, Query, TokenData},
    mail,
    model::Status,
    user::{Role, UserDocument, UserError},
    utils, GlobalConfig,
};

use super::{send_reset_mail, send_verification_mail, ActionClaims, ActionError, ActionType};

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
    State(db): State<Database>,
    State(global): State<GlobalConfig>,
    State(hibp): State<Hibp>,
    State(mail): State<mail::Client>,
    State(config): State<TokenConfig>,
    Json(body): Json<RegisterRequest>,
) -> crate::Result<Status> {
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

    db.insert_user(&user).await?;

    send_verification_mail(&user.email, &user.id.to_hex(), mail, config).await?;

    Ok(Status::new(StatusCode::CREATED, "user registered"))
}

pub async fn verify_email(
    TokenData(claims): TokenData<ActionClaims>,
    State(db): State<Database>,
) -> crate::Result<Status> {
    if claims.r#type != ActionType::Verify {
        return Err(ActionError::InvalidToken.into());
    }

    let addr = claims.email.ok_or(ActionError::InvalidToken)?;

    let user_id = ObjectId::parse_str(claims.sub).unwrap();

    let user = db.get_user(doc! {"_id": user_id }).await?;

    if user.email != addr {
        return Err(ActionError::InvalidToken.into());
    }
    if user.verified {
        return Err(ActionError::AlreadyVerified.into());
    }

    db.update_user_by_id(user_id, doc! { "verified": true })
        .await?;

    Ok(Status::new(StatusCode::OK, "account verified"))
}

#[derive(Debug, Deserialize)]
pub struct ResetOptions {
    email: String,
}

pub async fn request_reset(
    Query(opts): Query<ResetOptions>,
    State(db): State<Database>,
    State(mail): State<mail::Client>,
    State(config): State<TokenConfig>,
) -> crate::Result<Status> {
    let user = db.get_user(doc! { "email": opts.email }).await?;

    if !user.verified {
        return Err(ActionError::NotVerified.into());
    }

    send_reset_mail(&user.email, &user.id.to_hex(), mail, config).await?;

    Ok(Status::new(StatusCode::OK, "reset email sent"))
}

#[derive(Debug, Deserialize)]
pub struct ResetRequest {
    password: String,
}

pub async fn reset_password(
    TokenData(claims): TokenData<ActionClaims>,
    State(db): State<Database>,
    Json(body): Json<ResetRequest>,
) -> crate::Result<Status> {
    if claims.r#type != ActionType::Reset {
        return Err(ActionError::InvalidToken.into());
    }

    let user_id = ObjectId::parse_str(claims.sub).unwrap();

    let password_hash = password::validate_and_hash(&body.password)?;

    db.update_user_by_id(user_id, doc! { "password": password_hash })
        .await?;

    Ok(Status::new(StatusCode::OK, "new password set"))
}
