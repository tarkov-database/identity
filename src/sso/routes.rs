use std::sync::Arc;

use crate::AppState;

use super::{github, GitHub};

use axum::{routing::get, Router};
use tower_http::add_extension::AddExtensionLayer;

/// SSO routes
pub fn routes(state: Arc<AppState>, gh: GitHub) -> axum::Router<AppState> {
    let github_svc = Router::with_state_arc(state.clone())
        .route("/authorize", get(github::authorize))
        .route("/authorized", get(github::authorized))
        .layer(AddExtensionLayer::new(gh));

    Router::with_state_arc(state).nest("/github", github_svc)
}
