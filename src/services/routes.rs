use crate::AppState;

use super::{action, client, oauth, service, session, sso, token, user};

use axum::Router;

/// Token routes
pub fn routes(state: AppState) -> Router<()> {
    Router::new()
        .nest("/user", user::routes())
        .nest("/client", client::routes())
        .nest("/session", session::routes())
        .nest("/service", service::routes())
        .nest("/token", token::routes())
        .nest("/oauth", oauth::routes())
        .nest("/sso", sso::routes())
        .nest("/action", action::routes())
        .with_state(state)
}
