use axum::routing::post;

use super::handler;

/// Session routes
pub fn routes() -> axum::Router {
    axum::Router::new().route("/", post(handler::create))
}
