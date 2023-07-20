use crate::state::AppState;

use super::handler;

use axum::{routing::post, Router};

/// OAuth routes
pub fn routes() -> axum::Router<AppState> {
    Router::new().route("/token", post(handler::create_token))
}
