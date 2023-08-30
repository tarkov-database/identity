use crate::AppState;

use super::{action, client, health, oauth, service, session, sso, token, user};

use axum::Router;
use tower_http::cors::CorsLayer;

/// Service routes
pub fn routes(state: AppState, config: RouteConfig) -> Router<()> {
    Router::new()
        .nest("/user", user::routes(config.clone()))
        .nest("/client", client::routes(config.clone()))
        .nest("/session", session::routes(config.clone()))
        .nest("/service", service::routes(config.clone()))
        .nest("/token", token::routes(config.clone()))
        .nest("/oauth", oauth::routes(config.clone()))
        .nest("/sso", sso::routes(config.clone()))
        .nest("/action", action::routes(config.clone()))
        .nest("/health", health::routes(config))
        .with_state(state)
}

#[derive(Debug, Clone)]
pub struct RouteConfig {
    pub cors: CorsLayer,
}
