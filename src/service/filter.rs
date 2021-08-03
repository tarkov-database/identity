use crate::{
    authentication::token::{with_auth, TokenConfig},
    database::{with_db, Database},
    model,
    session::SessionClaims,
    utils::crypto::{with_aead, Aead256},
};

use super::handler;

use warp::Filter;

/// User filters combined.
pub fn filters(
    db: Database,
    config: TokenConfig,
    enc: Aead256,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    list(db.clone(), config.clone())
        .or(get(db.clone(), config.clone()))
        .or(create(db.clone(), config.clone(), enc.clone()))
        .or(update(db.clone(), config.clone(), enc))
        .or(delete(db, config))
}

/// GET /?offset=3&limit=5
fn list(
    db: Database,
    config: TokenConfig,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path::end()
        .and(warp::get())
        .and(with_auth::<SessionClaims>(config))
        .and(warp::query::<handler::Filter>())
        .and(warp::query::<model::ListOptions>())
        .and(with_db(db))
        .and_then(handler::list)
}

/// GET /:id with JSON body
fn get(
    db: Database,
    config: TokenConfig,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path::param::<String>()
        .and(warp::get())
        .and(with_auth::<SessionClaims>(config))
        .and(with_db(db))
        .and_then(handler::get_by_id)
}

/// POST / with JSON body
fn create(
    db: Database,
    config: TokenConfig,
    enc: Aead256,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path::end()
        .and(warp::post())
        .and(with_auth::<SessionClaims>(config))
        .and(warp::body::content_length_limit(1024 * 16).and(warp::body::json()))
        .and(with_db(db))
        .and(with_aead(enc))
        .and_then(handler::create)
}

/// PATCH /:id with JSON body
fn update(
    db: Database,
    config: TokenConfig,
    enc: Aead256,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path::param::<String>()
        .and(warp::patch())
        .and(with_auth::<SessionClaims>(config))
        .and(warp::body::content_length_limit(1024 * 16).and(warp::body::json()))
        .and(with_db(db))
        .and(with_aead(enc))
        .and_then(handler::update)
}

/// DELETE /:id
fn delete(
    db: Database,
    config: TokenConfig,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path::param::<String>()
        .and(warp::delete())
        .and(with_auth::<SessionClaims>(config))
        .and(with_db(db))
        .and_then(handler::delete)
}
