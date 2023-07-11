use crate::AppState;

use super::handler;

use axum::routing::{get, post};

/// User routes
pub fn routes() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/", get(handler::list).post(handler::create))
        .route(
            "/:id",
            get(handler::get_by_id)
                .patch(handler::update)
                .delete(handler::delete),
        )
        .route("/:id/token", post(handler::create_token))
}
