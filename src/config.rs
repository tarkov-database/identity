use crate::{mail, state::AppState, utils::serde::deserialize_vec_from_string};

use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};

use axum::extract::FromRef;
use http::HeaderValue;
use reqwest::Url;
use serde::Deserialize;

const fn default_addr() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

const fn default_port() -> u16 {
    8080
}

const fn default_hibp_check() -> bool {
    true
}

const fn default_health_interval() -> u64 {
    30
}

const fn default_health_latency_treshold() -> u64 {
    100
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    // HTTP server
    #[serde(default = "default_addr")]
    pub server_addr: IpAddr,
    #[serde(default = "default_port")]
    pub server_port: u16,
    #[serde(default)]
    pub server_tls: bool,
    pub server_tls_cert: Option<PathBuf>,
    pub server_tls_key: Option<PathBuf>,

    // MongoDB client
    pub mongo_uri: String,
    pub mongo_db: String,
    #[serde(default)]
    pub mongo_tls: bool,
    pub mongo_cert_key: Option<PathBuf>,
    pub mongo_ca: Option<PathBuf>,

    // Email client
    pub mail_from: String,
    pub mg_region: mail::Region,
    pub mg_domain: String,
    pub mg_key: String,

    // GitHub OAuth
    pub gh_client_id: String,
    pub gh_client_secret: String,
    pub gh_redirect_uri: Url,

    // Token
    pub token_trust_anchor: PathBuf,
    pub token_certs: PathBuf,
    pub token_key: PathBuf,

    // Crypto
    pub crypto_key: String,

    // Health
    #[serde(default = "default_health_interval")]
    pub health_interval: u64,
    #[serde(default = "default_health_latency_treshold")]
    pub health_latency_treshold: u64,

    // Global vars
    pub editor_mail_address: Vec<String>,
    pub allowed_domains: Vec<String>,
    #[serde(default = "default_hibp_check")]
    pub hibp_check: bool,

    #[serde(deserialize_with = "deserialize_vec_from_string")]
    pub cors_allowed_origins: Vec<HeaderValue>,
}

#[derive(Debug, Clone)]
pub struct GlobalConfig {
    pub allowed_domains: Vec<String>,
    pub editor_mail_addrs: Vec<String>,
}

impl GlobalConfig {
    pub fn is_allowed_domain<D>(&self, domain: D) -> bool
    where
        D: AsRef<str>,
    {
        let domain = domain.as_ref();
        self.allowed_domains.iter().any(|d| d == domain || d == "*")
    }

    pub fn is_editor_address<A>(&self, addr: A) -> bool
    where
        A: AsRef<str>,
    {
        let addr = addr.as_ref();
        self.editor_mail_addrs.iter().any(|d| d == addr)
    }
}

impl FromRef<AppState> for GlobalConfig {
    fn from_ref(state: &AppState) -> Self {
        state.global_config.clone()
    }
}
