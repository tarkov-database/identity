use crate::AppState;

use super::handler;

use std::sync::Arc;

use axum::routing::get;

/// Token routes
pub fn routes(state: Arc<AppState>) -> axum::Router<AppState> {
    axum::Router::with_state_arc(state).route("/", get(handler::get).post(handler::create))
}
