mod auth;
mod config;
mod crypto;
mod database;
mod error;
mod health;
mod http;
mod mail;
mod services;
mod state;
mod utils;

use crate::{
    config::{AppConfig, GlobalConfig},
    state::AppState,
};

use std::{
    fs::read,
    io::{stdout, IsTerminal},
    net::SocketAddr,
    time::Duration,
};

use axum::{error_handling::HandleErrorLayer, Router, Server};
use error::Error;
use hyper::{
    header::{AUTHORIZATION, COOKIE},
    server::conn::AddrIncoming,
};
use hyper_rustls::server::TlsAcceptor;
use services::routes::RouteConfig;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    sensitive_headers::SetSensitiveHeadersLayer,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
    LatencyUnit,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[cfg(feature = "mimalloc")]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub type Result<T> = std::result::Result<T, Error>;

enum LogFormat {
    Json,
    Pretty,
    Compact,
    Full,
}

impl LogFormat {
    fn from_env() -> Self {
        match std::env::var("LOG_FORMAT").as_deref() {
            Ok("json") => Self::Json,
            Ok("pretty") => Self::Pretty,
            Ok("compact") => Self::Compact,
            Ok("full") => Self::Full,
            _ => Self::Full,
        }
    }
}

fn init_tracing() {
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "RUST_LOG=info".into()),
    );

    match LogFormat::from_env() {
        LogFormat::Json => {
            let fmt_layer = tracing_subscriber::fmt::layer().json();
            subscriber.with(fmt_layer).init();
        }
        LogFormat::Pretty => {
            let fmt_layer = tracing_subscriber::fmt::layer()
                .pretty()
                .with_ansi(stdout().is_terminal());
            subscriber.with(fmt_layer).init();
        }
        LogFormat::Compact => {
            let fmt_layer = tracing_subscriber::fmt::layer()
                .compact()
                .with_ansi(stdout().is_terminal());
            subscriber.with(fmt_layer).init();
        }
        LogFormat::Full => {
            let fmt_layer = tracing_subscriber::fmt::layer().with_ansi(stdout().is_terminal());
            subscriber.with(fmt_layer).init();
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let prefix = envy::prefixed("IDENTITY_");

    let app_config: AppConfig = if dotenv::dotenv().is_ok() {
        prefix.from_iter(dotenv::vars())?
    } else {
        prefix.from_env()?
    };

    let state = AppState::from_config(app_config.clone()).await?;

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

    let route_config = RouteConfig {
        cors: CorsLayer::new()
            .allow_origin(app_config.cors_allowed_origins)
            .max_age(Duration::from_secs(app_config.cors_max_age)),
    };

    let svc_routes: Router<()> = services::routes(state, route_config);

    let routes = Router::new()
        .nest("/v1", svc_routes)
        .layer(middleware.into_inner());

    let server_addr = SocketAddr::from((app_config.server_addr, app_config.server_port));
    let incoming = AddrIncoming::bind(&server_addr)?;

    let signal_tx = utils::shutdown_signal(1);
    let mut signal_rx = signal_tx.subscribe();
    let graceful_shutdown = async move {
        signal_rx.recv().await.ok();
    };

    if app_config.server_tls {
        let certs = {
            let path = app_config
                .server_tls_cert
                .ok_or(Error::MissingConfigVar("IDENTITY_SERVER_TLS_CERT"))?;
            utils::pem::read_certs(&read(path)?[..])?
                .into_iter()
                .map(rustls::Certificate)
                .collect()
        };
        let key = {
            let path = app_config
                .server_tls_key
                .ok_or(Error::MissingConfigVar("IDENTITY_SERVER_TLS_KEY"))?;
            utils::pem::read_key(&read(path)?[..]).map(rustls::PrivateKey)?
        };

        let incoming = TlsAcceptor::builder()
            .with_single_cert(certs, key)?
            .with_all_versions_alpn()
            .with_incoming(incoming);
        let server = Server::builder(incoming)
            .serve(routes.into_make_service())
            .with_graceful_shutdown(graceful_shutdown);

        tracing::info!(
            ipAddress = %server_addr.ip(),
            port = %server_addr.port(),
            "HTTPS server started"
        );

        server.await?;
    } else {
        let server = Server::builder(incoming)
            .serve(routes.into_make_service())
            .with_graceful_shutdown(graceful_shutdown);

        tracing::info!(
            ipAddress = %server_addr.ip(),
            port = %server_addr.port(),
            "HTTP server started"
        );

        server.await?;
    }

    Ok(())
}
