use crate::Result;

use std::time::Duration;

use reqwest::Url;
use serde::Serialize;

#[derive(Debug, Serialize)]
struct Message<'a> {
    from: &'a str,
    to: &'a str,
    subject: &'a str,
    text: &'a str,
}

#[derive(Debug, Clone)]
pub struct Client {
    from: String,
    base: Url,
    api_key: String,
    client: reqwest::Client,
}

impl Client {
    const USER_AGENT: &'static str =
        concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

    const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

    pub fn new<S: AsRef<str>>(api_key: S, region: Region, domain: S, from: S) -> Result<Self> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .timeout(Self::DEFAULT_TIMEOUT)
            .user_agent(Self::USER_AGENT)
            .build()?;

        let mut base = region.base_url();
        base.set_path(&format!("v3/{}", domain.as_ref()));

        Ok(Self {
            from: from.as_ref().to_string(),
            base,
            api_key: api_key.as_ref().to_string(),
            client,
        })
    }

    pub async fn send<S: AsRef<str>>(&self, addr: S, sub: S, msg: S) -> Result<()> {
        let message = Message {
            from: self.from.as_str(),
            to: addr.as_ref(),
            subject: sub.as_ref(),
            text: msg.as_ref(),
        };

        let res = self
            .client
            .post(self.base.join("messages/").unwrap())
            .basic_auth("api", Some(&self.api_key))
            .form(&message)
            .send()
            .await?;

        res.error_for_status()?;

        Ok(())
    }
}

#[derive(Debug)]
pub enum Region {
    US,
    EU,
}

impl Region {
    fn base_url(&self) -> Url {
        match self {
            Region::US => Url::parse("https://api.mailgun.net/").unwrap(),
            Region::EU => Url::parse("https://api.eu.mailgun.net/").unwrap(),
        }
    }
}
