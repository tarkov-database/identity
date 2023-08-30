use crate::{services::routes::RouteConfig, AppState};

use super::handler;

use axum::routing::{get, post};
use http::{header, Method, StatusCode};

/// Action routes
pub fn routes(config: RouteConfig) -> axum::Router<AppState> {
    axum::Router::new()
        .route(
            "/register",
            post(handler::register)
                .options(|| async { StatusCode::NO_CONTENT })
                .route_layer(
                    config
                        .cors
                        .clone()
                        .allow_methods([Method::POST, Method::OPTIONS]),
                ),
        )
        .route(
            "/verify",
            get(handler::verify_email)
                .options(|| async { StatusCode::NO_CONTENT })
                .route_layer(
                    config
                        .cors
                        .clone()
                        .allow_methods([Method::GET, Method::OPTIONS])
                        .allow_headers([header::AUTHORIZATION]),
                ),
        )
        .route(
            "/reset",
            get(handler::request_reset)
                .post(handler::reset_password)
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
            "/change-email",
            post(handler::change_email)
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
