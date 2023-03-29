mod action;
mod authentication;
mod client;
mod config;
mod database;
mod error;
mod extract;
mod http;
mod mail;
mod model;
mod service;
mod session;
mod sso;
mod token;
mod user;
mod utils;

use crate::{
    authentication::{
        password::{Hasher, Hibp, Password},
        token::TokenConfig,
    },
    config::{AppConfig, GlobalConfig},
    database::Database,
    error::handle_error,
    http::HttpClient,
    sso::GitHub,
    utils::crypto::Aead256,
};

use std::{env, iter::once, net::SocketAddr, time::Duration};

use axum::{error_handling::HandleErrorLayer, Router, Server};
use hyper::header::AUTHORIZATION;
use mongodb::options::{ClientOptions, Tls, TlsOptions};
use tower::ServiceBuilder;
use tower_http::{
    sensitive_headers::SetSensitiveHeadersLayer,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
    LatencyUnit,
};

#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

pub type Result<T> = std::result::Result<T, error::Error>;

#[derive(Clone)]
pub struct AppState {
    mail_client: mail::Client,
    database: Database,
    password: Password,
    aead: Aead256,
    global_config: GlobalConfig,
    token_config: TokenConfig,
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
    let client = HttpClient::default();
    let token_config =
        TokenConfig::from_secret(app_config.jwt_secret.as_bytes(), app_config.jwt_audience);
    let aead = Aead256::new(app_config.crypto_key)?;
    let hibp = Hibp::with_client(client.clone());
    let password = Password::new(Hasher::default(), hibp, app_config.hibp_check);
    let mail = mail::Client::new(
        app_config.mg_key,
        app_config.mg_region,
        app_config.mg_domain,
        app_config.mail_from,
        client.clone(),
    )?;
    let github = GitHub::new(
        app_config.gh_client_id,
        app_config.gh_client_secret,
        app_config.gh_redirect_uri,
        client,
    )?;
    let global_config = GlobalConfig {
        allowed_domains: app_config.allowed_domains,
        editor_mail_addrs: app_config.editor_mail_address,
    };

    let state = AppState {
        mail_client: mail,
        database: db,
        aead,
        password,
        global_config,
        token_config,
    };

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
        );

    let svc_routes: Router<()> = Router::new()
        .nest("/user", user::routes())
        .nest("/client", client::routes())
        .nest("/session", session::routes())
        .nest("/service", service::routes())
        .nest("/token", token::routes())
        .nest("/sso", sso::routes(github))
        .nest("/action", action::routes())
        .with_state(state);

    let routes = Router::new()
        .nest("/v1", svc_routes)
        .layer(middleware.into_inner());

    let addr = SocketAddr::from((app_config.server_addr, app_config.server_port));
    let server =
        Server::bind(&addr).serve(routes.into_make_service_with_connect_info::<SocketAddr>());

    let signal_tx = utils::shutdown_signal(1);
    let mut signal_rx = signal_tx.subscribe();
    let server = server.with_graceful_shutdown(async move {
        signal_rx.recv().await.ok();
    });

    tracing::debug!(
        ipAddress =? addr.ip(),
        port =? addr.port(),
        "HTTP(S) server started"
    );

    server.await?;

    Ok(())
}
