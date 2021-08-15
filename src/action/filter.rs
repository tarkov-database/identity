use crate::{
    authentication::token::{with_auth, with_config, TokenConfig},
    database::{with_db, Database},
    mail::{self, with_mail},
};

use super::{handler, ActionClaims};

use warp::Filter;

/// Action filters combined.
pub fn filters(
    db: Database,
    config: TokenConfig,
    mail: mail::Client,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    verify(db.clone(), config.clone())
        .or(get_reset(db.clone(), config.clone(), mail))
        .or(post_reset(db, config))
}

/// GET /verify
fn verify(
    db: Database,
    config: TokenConfig,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path::path("verify")
        .and(warp::get())
        .and(with_auth::<ActionClaims>(config))
        .and(with_db(db))
        .and_then(handler::verify_email)
}

/// GET /reset?email=<address>
fn get_reset(
    db: Database,
    config: TokenConfig,
    mail: mail::Client,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path::path("reset")
        .and(warp::get())
        .and(warp::query::<handler::ResetOptions>())
        .and(with_db(db))
        .and(with_mail(mail))
        .and(with_config(config))
        .and_then(handler::request_reset)
}

/// POST /reset
fn post_reset(
    db: Database,
    config: TokenConfig,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path::path("reset")
        .and(warp::post())
        .and(with_auth::<ActionClaims>(config))
        .and(warp::body::content_length_limit(1024 * 16).and(warp::body::json()))
        .and(with_db(db))
        .and_then(handler::reset_password)
}
