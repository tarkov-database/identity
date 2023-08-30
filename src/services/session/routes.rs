use crate::{services::routes::RouteConfig, AppState};

use super::handler;

use axum::routing::post;
use http::{header, Method, StatusCode};

/// Session routes
pub fn routes(config: RouteConfig) -> axum::Router<AppState> {
    axum::Router::new().route(
        "/",
        post(handler::create)
            .get(handler::refresh)
            .options(|| async { StatusCode::NO_CONTENT })
            .route_layer(
                config
                    .cors
                    .clone()
                    .allow_methods([Method::POST, Method::GET, Method::OPTIONS])
                    .allow_headers([
                        header::AUTHORIZATION,
                        header::CONTENT_TYPE,
                        header::ACCEPT,
                        header::CONTENT_LENGTH,
                    ]),
            ),
    )
}
