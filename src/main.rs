mod action;
mod authentication;
mod client;
mod database;
mod error;
mod extract;
mod mail;
mod model;
mod service;
mod session;
mod token;
mod user;
mod utils;

use crate::{
    authentication::token::TokenConfig, database::Database, error::handle_error,
    utils::crypto::Aead256,
};

use std::{
    env,
    iter::once,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use axum::{error_handling::HandleErrorLayer, Router, Server};
use hyper::header::AUTHORIZATION;
use mongodb::options::{ClientOptions, Tls, TlsOptions};
use serde::Deserialize;
use tower::ServiceBuilder;
use tower_http::{
    add_extension::AddExtensionLayer,
    sensitive_headers::SetSensitiveHeadersLayer,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
    LatencyUnit,
};

#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

pub type Result<T> = std::result::Result<T, error::Error>;

const fn default_addr() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

const fn default_port() -> u16 {
    8080
}

#[derive(Debug, Deserialize)]
struct AppConfig {
    // HTTP server
    #[serde(default = "default_addr")]
    server_addr: IpAddr,
    #[serde(default = "default_port")]
    server_port: u16,

    // MongoDB client
    mongo_uri: String,
    mongo_db: String,
    #[serde(default)]
    mongo_tls: bool,
    mongo_cert_key: Option<PathBuf>,
    mongo_ca: Option<PathBuf>,

    // Email client
    mail_from: String,
    mg_region: mail::Region,
    mg_domain: String,
    mg_key: String,

    // JWT
    jwt_secret: String,
    jwt_audience: Vec<String>,

    // Crypto
    crypto_key: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt::init();

    let prefix = envy::prefixed("IDENTITY_");

    let app_config: AppConfig = if dotenv::dotenv().is_ok() {
        prefix.from_iter(dotenv::vars())?
    } else {
        prefix.from_env()?
    };

    let mut mongo_opts = ClientOptions::parse(app_config.mongo_uri).await?;

    if app_config.mongo_tls {
        let opts = TlsOptions::builder()
            .cert_key_file_path(app_config.mongo_cert_key)
            .ca_file_path(app_config.mongo_ca);

        mongo_opts.tls = Some(Tls::Enabled(opts.build()));
    }

    let db = Database::new(mongo_opts, &app_config.mongo_db)?;
    let token_config =
        TokenConfig::from_secret(app_config.jwt_secret.as_bytes(), app_config.jwt_audience);
    let aead = Aead256::new(app_config.crypto_key).unwrap();
    let mail = mail::Client::new(
        app_config.mg_key,
        app_config.mg_region,
        app_config.mg_domain,
        app_config.mail_from,
    )?;

    let middleware = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(handle_error))
        .load_shed()
        .concurrency_limit(1024)
        .timeout(Duration::from_secs(60))
        .layer(SetSensitiveHeadersLayer::new(once(AUTHORIZATION)))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().include_headers(true))
                .on_response(
                    DefaultOnResponse::new()
                        .include_headers(true)
                        .latency_unit(LatencyUnit::Micros),
                ),
        )
        .layer(AddExtensionLayer::new(db))
        .layer(AddExtensionLayer::new(token_config))
        .layer(AddExtensionLayer::new(aead))
        .layer(AddExtensionLayer::new(mail));

    let svc_routes = Router::new()
        .nest("/user", user::routes())
        .nest("/client", client::routes())
        .nest("/session", session::routes())
        .nest("/service", service::routes())
        .nest("/token", token::routes())
        .nest("/action", action::routes());

    let routes = Router::new()
        .nest("/v1", svc_routes)
        .layer(middleware.into_inner());

    let addr = SocketAddr::from((app_config.server_addr, app_config.server_port));
    tracing::debug!("listening on {}", addr);
    let server =
        Server::bind(&addr).serve(routes.into_make_service_with_connect_info::<SocketAddr, _>());

    let signal_tx = utils::shutdown_signal(1);
    let mut signal_rx = signal_tx.subscribe();
    let server = server.with_graceful_shutdown(async move {
        signal_rx.recv().await.ok();
    });

    server.await?;

    Ok(())
}
