use crate::state::AppState;

use super::github;

use axum::{routing::get, Router};

/// SSO routes
pub fn routes() -> axum::Router<AppState> {
    let github_svc = Router::new()
        .route("/authorize", get(github::authorize))
        .route("/authorized", get(github::authorized));

    Router::new().nest("/github", github_svc)
}
