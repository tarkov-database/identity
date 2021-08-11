use crate::{database::Database, error::Error, model::Status};

use super::{ActionClaims, ActionError};

use mongodb::bson::{doc, oid::ObjectId};
use warp::{http::StatusCode, reply, Rejection};

pub async fn email_verification(
    claims: ActionClaims,
    db: Database,
) -> std::result::Result<reply::Response, Rejection> {
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
