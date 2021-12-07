use axum::routing::get;

use super::handler;

/// Session routes
pub fn routes() -> axum::Router {
    axum::Router::new()
        .route("/verify", get(handler::verify_email))
        .route(
            "/reset",
            get(handler::request_reset).post(handler::reset_password),
        )
}
