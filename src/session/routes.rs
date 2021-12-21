use super::handler;

use axum::routing::post;

/// Session routes
pub fn routes() -> axum::Router {
    axum::Router::new().route("/", post(handler::create))
}
