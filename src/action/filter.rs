use crate::{
    authentication::token::{with_auth, TokenConfig},
    database::{self, Database},
};

use super::{handler, ActionClaims};

use warp::Filter;

/// Action filters combined.
pub fn filters(
    db: Database,
    config: TokenConfig,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    email_verification(db, config)
}

/// GET /verify
fn email_verification(
    db: Database,
    config: TokenConfig,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path::path("verify")
        .and(warp::get())
        .and(with_auth::<ActionClaims>(config))
        .and(database::with_db(db))
        .and_then(handler::email_verification)
}
