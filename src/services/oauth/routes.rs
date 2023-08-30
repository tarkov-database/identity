use crate::{services::routes::RouteConfig, state::AppState};

use super::handler;

use axum::{routing::post, Router};
use http::{header, Method, StatusCode};

/// OAuth routes
pub fn routes(config: RouteConfig) -> axum::Router<AppState> {
    Router::new().route(
        "/token",
        post(handler::create_token)
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
