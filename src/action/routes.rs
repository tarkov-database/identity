use crate::AppState;

use super::handler;

use std::sync::Arc;

use axum::routing::{get, post};

/// Action routes
pub fn routes(state: Arc<AppState>) -> axum::Router<AppState> {
    axum::Router::with_state_arc(state)
        .route("/register", post(handler::register))
        .route("/verify", get(handler::verify_email))
        .route(
            "/reset",
            get(handler::request_reset).post(handler::reset_password),
        )
}
