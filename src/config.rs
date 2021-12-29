use crate::mail;

use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};

use reqwest::Url;
use serde::Deserialize;

const fn default_addr() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

const fn default_port() -> u16 {
    8080
}

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    // HTTP server
    #[serde(default = "default_addr")]
    pub server_addr: IpAddr,
    #[serde(default = "default_port")]
    pub server_port: u16,

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

    // JWT
    pub jwt_secret: String,
    pub jwt_audience: Vec<String>,

    // Crypto
    pub crypto_key: String,

    // Global vars
    pub allowed_domains: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct GlobalConfig {
    pub allowed_domains: Vec<String>,
}

impl GlobalConfig {
    pub fn is_domain_allowed<D>(&self, domain: D) -> bool
    where
        D: AsRef<str>,
    {
        let domain = domain.as_ref();
        self.allowed_domains.iter().any(|d| d == domain || d == "*")
    }
}
