mod action;
mod authentication;
mod client;
mod database;
mod error;
mod mail;
mod model;
mod service;
mod session;
mod token;
mod user;
mod utils;

use crate::authentication::token::TokenConfig;
use crate::database::Database;
use crate::utils::crypto::Aead256;

use std::env;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use mongodb::options::ClientOptions;
use serde::Deserialize;
use warp::Filter;

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
    mongo_cert: Option<PathBuf>,
    mongo_key: Option<PathBuf>,

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
    env_logger::init();

    let prefix = envy::prefixed("IDENTITY_");

    let app_config: AppConfig = if dotenv::dotenv().is_ok() {
        prefix.from_iter(dotenv::vars())?
    } else {
        prefix.from_env()?
    };

    let mongo_opts = ClientOptions::parse(app_config.mongo_uri).await?;

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

    let user_filter = user::filters(db.clone(), token_config.clone(), mail);
    let client_filter = client::filters(db.clone(), token_config.clone());
    let session_filter = session::filters(db.clone(), token_config.clone());
    let service_filter = service::filters(db.clone(), token_config.clone(), aead.clone());
    let token_filter = token::filters(db.clone(), token_config.clone(), aead);
    let action_filter = action::filters(db, token_config);

    let svc_routes = warp::path("user")
        .and(user_filter)
        .or(warp::path("client").and(client_filter))
        .or(warp::path("session").and(session_filter))
        .or(warp::path("service").and(service_filter))
        .or(warp::path("token").and(token_filter))
        .or(warp::path("action").and(action_filter));

    let routes = warp::path("v1")
        .and(svc_routes)
        .recover(error::handle_rejection);

    warp::serve(routes)
        .run((app_config.server_addr, app_config.server_port))
        .await;

    Ok(())
}
