use crate::{services::routes::RouteConfig, state::AppState};

use super::github;

use axum::{routing::get, Router};
use http::{header, Method, StatusCode};

/// SSO routes
pub fn routes(config: RouteConfig) -> axum::Router<AppState> {
    let github_svc = Router::new()
        .route(
            "/authorize",
            get(github::authorize)
                .options(|| async { StatusCode::NO_CONTENT })
                .route_layer(
                    config
                        .cors
                        .clone()
                        .allow_methods([Method::GET, Method::OPTIONS]),
                ),
        )
        .route(
            "/authorized",
            get(github::authorized)
                .options(|| async { StatusCode::NO_CONTENT })
                .route_layer(
                    config
                        .cors
                        .clone()
                        .allow_methods([Method::GET, Method::OPTIONS])
                        .allow_headers([header::COOKIE])
                        .allow_credentials(true),
                ),
        );

    Router::new().nest("/github", github_svc)
}
