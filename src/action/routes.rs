use super::handler;

use axum::routing::{get, post};

/// Action routes
pub fn routes() -> axum::Router {
    axum::Router::new()
        .route("/register", post(handler::register))
        .route("/verify", get(handler::verify_email))
        .route(
            "/reset",
            get(handler::request_reset).post(handler::reset_password),
        )
}
