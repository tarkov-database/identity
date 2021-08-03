use crate::{
    authentication::token::{self, TokenConfig},
    database::{self, Database},
};

use super::handler;

use warp::Filter;

/// User filters combined.
pub fn filters(
    db: Database,
    config: TokenConfig,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    create(db, config)
}

/// POST / with JSON body
fn create(
    db: Database,
    config: TokenConfig,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::path::end()
        .and(warp::post())
        .and(warp::body::content_length_limit(1024 * 16).and(warp::body::json()))
        .and(database::with_db(db))
        .and(token::with_config(config))
        .and_then(handler::create)
}
