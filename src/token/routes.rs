use axum::routing::get;

use super::handler;

/// Token routes
pub fn routes() -> axum::Router {
    axum::Router::new().route("/", get(handler::get).post(handler::create))
}
