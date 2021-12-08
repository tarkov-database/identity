use crate::{
    action::{send_reset_mail, ActionType},
    authentication::{password, token::TokenConfig},
    database::Database,
    extract::{Query, SizedJson},
    mail,
    model::Status,
};

use super::{ActionClaims, ActionError};

use axum::extract::Extension;
use hyper::StatusCode;
use mongodb::bson::{doc, oid::ObjectId};
use serde::Deserialize;

pub async fn verify_email(
    claims: ActionClaims,
    Extension(db): Extension<Database>,
) -> crate::Result<Status> {
    if claims.r#type != ActionType::Verify {
        return Err(ActionError::Invalid.into());
    }

    let addr = if let Some(v) = claims.email {
        v
    } else {
        return Err(ActionError::Invalid.into());
    };

    let user_id = ObjectId::parse_str(claims.sub).unwrap();

    let user = db.get_user(doc! {"_id": user_id }).await?;

    if user.email != addr {
        return Err(ActionError::Invalid.into());
    }
    if user.verified {
        return Err(ActionError::AlreadyVerified.into());
    }

    db.update_user(user_id, doc! { "verified": true }).await?;

    Ok(Status::new(StatusCode::OK, "account verified"))
}

#[derive(Debug, Deserialize)]
pub struct ResetOptions {
    email: String,
}

pub async fn request_reset(
    Query(opts): Query<ResetOptions>,
    Extension(db): Extension<Database>,
    Extension(mail): Extension<mail::Client>,
    Extension(config): Extension<TokenConfig>,
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
    claims: ActionClaims,
    SizedJson(body): SizedJson<ResetRequest>,
    Extension(db): Extension<Database>,
) -> crate::Result<Status> {
    if claims.r#type != ActionType::Reset {
        return Err(ActionError::Invalid.into());
    }

    let user_id = ObjectId::parse_str(claims.sub).unwrap();

    let password_hash = password::validate_and_hash(&body.password)?;

    db.update_user(user_id, doc! { "password": password_hash })
        .await?;

    Ok(Status::new(StatusCode::OK, "new password set"))
}
