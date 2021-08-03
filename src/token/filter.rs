use crate::{
    authentication::token::{self, with_auth, TokenConfig},
    database::{with_db, Database},
    session::SessionClaims,
    utils::crypto::{with_aead, Aead256},
};

use super::{handler, ClientClaims};

use warp::Filter;

/// User filters combined.
pub fn filters(
    db: Database,
    config: TokenConfig,
    enc: Aead256,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    get(db.clone(), config.clone(), enc).or(create(db, config))
}

/// GET /
fn get(
    db: Database,
    config: TokenConfig,
    enc: Aead256,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path::end()
        .and(warp::get())
        .and(with_auth::<ClientClaims>(config.clone()))
        .and(with_db(db))
        .and(with_aead(enc))
        .and(token::with_config(config))
        .and_then(handler::get)
}

/// POST / with JSON body
fn create(
    db: Database,
    config: TokenConfig,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path::end()
        .and(warp::post())
        .and(with_auth::<SessionClaims>(config.clone()))
        .and(warp::body::content_length_limit(1024 * 16).and(warp::body::json()))
        .and(with_db(db))
        .and(token::with_config(config))
        .and_then(handler::create)
}
