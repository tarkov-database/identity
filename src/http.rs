use std::{ops::Deref, time::Duration};

use reqwest::{redirect, tls};

#[derive(Debug, Clone)]
pub struct HttpClient(reqwest::Client);

impl HttpClient {
    const USER_AGENT: &'static str =
        concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

    const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
    const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(60);
}

impl Deref for HttpClient {
    type Target = reqwest::Client;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        let client = reqwest::Client::builder()
            .https_only(true)
            .use_rustls_tls()
            .min_tls_version(tls::Version::TLS_1_2)
            .redirect(redirect::Policy::none())
            .tcp_keepalive(Self::KEEP_ALIVE_TIMEOUT)
            .timeout(Self::DEFAULT_TIMEOUT)
            .user_agent(Self::USER_AGENT)
            .build()
            .unwrap();

        Self(client)
    }
}
