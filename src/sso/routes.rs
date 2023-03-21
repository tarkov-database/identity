use crate::AppState;

use super::{github, GitHub};

use axum::{routing::get, Router};
use tower_http::add_extension::AddExtensionLayer;

/// SSO routes
pub fn routes(gh: GitHub) -> axum::Router<AppState> {
    let github_svc = Router::new()
        .route("/authorize", get(github::authorize))
        .route("/authorized", get(github::authorized))
        .layer(AddExtensionLayer::new(gh));

    Router::new().nest("/github", github_svc)
}
