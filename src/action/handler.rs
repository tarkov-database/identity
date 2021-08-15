use crate::{
    action::{send_reset_mail, ActionType},
    authentication::{password, token::TokenConfig},
    database::Database,
    error::Error,
    mail,
    model::Status,
};

use super::{ActionClaims, ActionError};

use mongodb::bson::{doc, oid::ObjectId};
use serde::Deserialize;
use warp::{http::StatusCode, reply, Rejection};

pub async fn verify_email(
    claims: ActionClaims,
    db: Database,
) -> std::result::Result<reply::Response, Rejection> {
    if claims.r#type != ActionType::Verify {
        return Err(Error::from(ActionError::Invalid).into());
    }

    let addr = if let Some(v) = claims.email {
        v
    } else {
        return Err(Error::from(ActionError::Invalid).into());
    };

    let user_id = ObjectId::parse_str(claims.sub).unwrap();

    let user = db.get_user(doc! {"_id": user_id }).await?;

    if user.email != addr {
        return Err(Error::from(ActionError::Invalid).into());
    }
    if user.verified {
        return Err(Error::from(ActionError::AlreadyVerified).into());
    }

    db.update_user(user_id, doc! { "verified": true }).await?;

    Ok(Status::new(StatusCode::OK, "account verified").into())
}

#[derive(Debug, Deserialize)]
pub struct ResetOptions {
    email: String,
}

pub async fn request_reset(
    req: ResetOptions,
    db: Database,
    mail: mail::Client,
    config: TokenConfig,
) -> std::result::Result<reply::Response, Rejection> {
    let user = db.get_user(doc! { "email": req.email }).await?;

    if !user.verified {
        return Err(Error::from(ActionError::NotVerified).into());
    }

    send_reset_mail(&user.email, &user.id.to_hex(), mail, config).await?;

    Ok(Status::new(StatusCode::OK, "reset email sent").into())
}

#[derive(Debug, Deserialize)]
pub struct ResetRequest {
    password: String,
}

pub async fn reset_password(
    claims: ActionClaims,
    body: ResetRequest,
    db: Database,
) -> std::result::Result<reply::Response, Rejection> {
    if claims.r#type != ActionType::Reset {
        return Err(Error::from(ActionError::Invalid).into());
    }

    let user_id = ObjectId::parse_str(claims.sub).unwrap();

    let password_hash = password::validate_and_hash(&body.password)?;

    db.update_user(user_id, doc! { "password": password_hash })
        .await?;

    Ok(Status::new(StatusCode::OK, "new password set").into())
}
