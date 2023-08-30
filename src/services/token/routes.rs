use crate::{services::routes::RouteConfig, AppState};

use super::handler;

use axum::routing::get;
use http::{header, Method, StatusCode};

/// Token routes
pub fn routes(config: RouteConfig) -> axum::Router<AppState> {
    axum::Router::new().route(
        "/",
        get(handler::get)
            .options(|| async { StatusCode::NO_CONTENT })
            .route_layer(
                config
                    .cors
                    .clone()
                    .allow_headers([
                        header::AUTHORIZATION,
                        header::CONTENT_TYPE,
                        header::ACCEPT,
                        header::CONTENT_LENGTH,
                    ])
                    .allow_methods([Method::GET, Method::OPTIONS]),
            ),
    )
}
