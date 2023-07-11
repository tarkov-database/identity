mod action;
mod auth;
mod client;
mod config;
mod crypto;
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
    auth::{
        password::{Hasher, Hibp, Password},
        token::sign::TokenSignerBuilder,
    },
    config::{AppConfig, GlobalConfig},
    crypto::{aead::Aead256, certificate::CertificateStore},
    database::Database,
    error::handle_error,
    http::HttpClient,
    sso::GitHub,
};

use std::{iter::once, net::SocketAddr, time::Duration};

use auth::token::{sign::TokenSigner, verify::TokenVerifier};
use axum::{error_handling::HandleErrorLayer, Router, Server};
use hyper::header::AUTHORIZATION;
use mongodb::options::{ClientOptions, Tls, TlsOptions};
use pki_rs::certificate::Certificate;
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

// TODO: improve and move app state
#[derive(Clone)]
pub struct AppState {
    mail_client: mail::Client,
    database: Database,
    password: Password,
    token_signer: TokenSigner,
    token_verifier: TokenVerifier,
    aead: Aead256,
    global_config: GlobalConfig,
}

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

    let mut mongo_opts = ClientOptions::parse(app_config.mongo_uri).await?;

    if app_config.mongo_tls {
        let opts = TlsOptions::builder()
            .cert_key_file_path(app_config.mongo_cert_key)
            .ca_file_path(app_config.mongo_ca);

        mongo_opts.tls = Some(Tls::Enabled(opts.build()));
    }

    // TODO: improve this
    let trust_anchor_file = tokio::fs::read(app_config.token_trust_anchor)
        .await
        .expect("failed to read trust anchor");
    let trust_anchor = utils::pem::read_cert(&trust_anchor_file[..])
        .map(Certificate::from_der)
        .expect("failed to read trust anchor")
        .expect("failed to parse trust anchor");

    let cert_store = CertificateStore::new(trust_anchor);

    let token_signer = TokenSignerBuilder::default()
        .set_key_path(app_config.token_key)
        .set_chain_path(app_config.token_certs)
        .set_store(cert_store.clone())
        .build()
        .await
        .expect("failed to build token signer");

    let token_verifier = TokenVerifier::new(cert_store);

    let db = Database::new(mongo_opts, &app_config.mongo_db)?;
    let client = HttpClient::default();
    let aead = Aead256::new_from_b64(app_config.crypto_key)?;
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
        token_signer,
        token_verifier,
        global_config,
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
