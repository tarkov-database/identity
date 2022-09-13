use crate::AppState;

use super::handler;

use std::sync::Arc;

use axum::routing::post;

/// Session routes
pub fn routes(state: Arc<AppState>) -> axum::Router<AppState> {
    axum::Router::with_state_arc(state).route("/", post(handler::create).get(handler::refresh))
}
