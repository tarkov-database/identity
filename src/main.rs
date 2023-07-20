mod auth;
mod config;
mod crypto;
mod database;
mod error;
mod http;
mod mail;
mod services;
mod state;
mod utils;

use crate::{
    config::{AppConfig, GlobalConfig},
    state::AppState,
};

use std::{net::SocketAddr, time::Duration};

use axum::{error_handling::HandleErrorLayer, Router, Server};
use hyper::header::{AUTHORIZATION, COOKIE};
use tower::ServiceBuilder;
use tower_http::{
    sensitive_headers::SetSensitiveHeadersLayer,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
    LatencyUnit,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

pub type Result<T> = std::result::Result<T, error::Error>;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "RUST_LOG=info".into()),
        )
        .with(tracing_subscriber::fmt::layer().pretty())
        .init();

    let prefix = envy::prefixed("IDENTITY_");

    let app_config: AppConfig = if dotenv::dotenv().is_ok() {
        prefix.from_iter(dotenv::vars())?
    } else {
        prefix.from_env()?
    };

    let server_addr = SocketAddr::from((app_config.server_addr, app_config.server_port));

    let state = AppState::from_config(app_config).await?;

    let middleware = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(services::error::handle_error))
        .load_shed()
        .concurrency_limit(1024)
        .timeout(Duration::from_secs(60))
        .layer(SetSensitiveHeadersLayer::new([AUTHORIZATION, COOKIE]))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().include_headers(true))
                .on_response(
                    DefaultOnResponse::new()
                        .include_headers(true)
                        .latency_unit(LatencyUnit::Micros),
                ),
        );

    let svc_routes: Router<()> = services::routes(state);

    let routes = Router::new()
        .nest("/v1", svc_routes)
        .layer(middleware.into_inner());

    let server = Server::bind(&server_addr)
        .serve(routes.into_make_service_with_connect_info::<SocketAddr>());

    let signal_tx = utils::shutdown_signal(1);
    let mut signal_rx = signal_tx.subscribe();
    let server = server.with_graceful_shutdown(async move {
        signal_rx.recv().await.ok();
    });

    tracing::debug!(
        ipAddress =? server_addr.ip(),
        port =? server_addr.port(),
        "HTTP(S) server started"
    );

    server.await?;

    Ok(())
}
