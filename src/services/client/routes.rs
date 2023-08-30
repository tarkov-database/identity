use crate::{services::routes::RouteConfig, AppState};

use super::handler;

use axum::routing::{get, post};
use http::{header, Method, StatusCode};

/// Client routes
pub fn routes(config: RouteConfig) -> axum::Router<AppState> {
    axum::Router::new()
        .route(
            "/",
            get(handler::list)
                .post(handler::create)
                .options(|| async { StatusCode::NO_CONTENT })
                .route_layer(
                    config
                        .cors
                        .clone()
                        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                        .allow_headers([
                            header::AUTHORIZATION,
                            header::CONTENT_TYPE,
                            header::ACCEPT,
                            header::CONTENT_LENGTH,
                        ]),
                ),
        )
        .route(
            "/:id",
            get(handler::get_by_id)
                .patch(handler::update)
                .delete(handler::delete)
                .options(|| async { StatusCode::NO_CONTENT })
                .route_layer(
                    config
                        .cors
                        .clone()
                        .allow_methods([
                            Method::GET,
                            Method::PATCH,
                            Method::DELETE,
                            Method::OPTIONS,
                        ])
                        .allow_headers([
                            header::AUTHORIZATION,
                            header::CONTENT_TYPE,
                            header::ACCEPT,
                            header::CONTENT_LENGTH,
                        ]),
                ),
        )
        .route(
            "/:id/credentials",
            post(handler::create_credentials)
                .options(|| async { StatusCode::NO_CONTENT })
                .route_layer(
                    config
                        .cors
                        .clone()
                        .allow_methods([Method::POST, Method::OPTIONS])
                        .allow_headers([
                            header::AUTHORIZATION,
                            header::CONTENT_TYPE,
                            header::ACCEPT,
                            header::CONTENT_LENGTH,
                        ]),
                ),
        )
}
