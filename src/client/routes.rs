use axum::routing::get;

use super::handler;

/// User routes
pub fn routes() -> axum::Router {
    axum::Router::new()
        .route("/", get(handler::list).post(handler::create))
        .route(
            "/:id",
            get(handler::get_by_id)
                .patch(handler::update)
                .delete(handler::delete),
        )
}
