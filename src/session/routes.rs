use crate::AppState;

use super::handler;

use axum::routing::post;

/// Session routes
pub fn routes() -> axum::Router<AppState> {
    axum::Router::new().route("/", post(handler::create).get(handler::refresh))
}
