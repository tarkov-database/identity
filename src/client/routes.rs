use std::sync::Arc;

use crate::AppState;

use super::handler;

use axum::routing::get;

/// User routes
pub fn routes(state: Arc<AppState>) -> axum::Router<AppState> {
    axum::Router::with_state_arc(state)
        .route("/", get(handler::list).post(handler::create))
        .route(
            "/:id",
            get(handler::get_by_id)
                .patch(handler::update)
                .delete(handler::delete),
        )
}
