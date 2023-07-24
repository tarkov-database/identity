use crate::{
    auth::token::{self},
    crypto::aead::AeadError,
};

use hyper_rustls::server::config::TlsConfigError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("crypto error: {0}")]
    Aead(#[from] AeadError),

    #[error("database error: {0}")]
    Database(#[from] mongodb::error::Error),

    #[error("Envy error: {0}")]
    Envy(#[from] envy::Error),

    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),

    #[error("token signer builder error: {0}")]
    TokenBuilder(#[from] token::sign::BuilderError),

    #[error("tls config error: {0}")]
    TlsConfig(#[from] TlsConfigError),

    #[error("missing config variable: {0}")]
    MissingConfigVariable(&'static str),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("pki error: {0}")]
    Pki(#[from] pki_rs::error::Error),
}
