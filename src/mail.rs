use crate::Result;

use std::{collections::HashMap, convert::Infallible, time::Duration};

use reqwest::Url;
use serde::{Deserialize, Serialize};
use warp::Filter;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
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

#[derive(Debug, Serialize)]
struct TextMessage<'a> {
    from: &'a str,
    to: &'a str,
    subject: &'a str,
    text: &'a str,
}

#[derive(Debug, Serialize)]
struct TemplateMessage<'a> {
    from: &'a str,
    to: &'a str,
    subject: &'a str,
    template: &'a str,
    #[serde(
        rename = "h:X-Mailgun-Variables",
        skip_serializing_if = "Option::is_none"
    )]
    variables: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct Client {
    from: String,
    base: Url,
    api_key: String,
    domain: String,
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

        let base = region.base_url().join("v3/").unwrap();

        Ok(Self {
            from: from.as_ref().to_string(),
            base,
            api_key: api_key.as_ref().to_string(),
            domain: domain.as_ref().to_string(),
            client,
        })
    }

    pub async fn send_text(&self, addr: &str, sub: &str, msg: &str) -> Result<()> {
        let message = TextMessage {
            from: self.from.as_str(),
            to: addr,
            subject: sub,
            text: msg,
        };

        self.send(&message).await
    }

    pub async fn send_template(
        &self,
        addr: &str,
        sub: &str,
        tmpl: &str,
        vars: HashMap<String, String>,
    ) -> Result<()> {
        let vars = serde_json::to_string(&vars).unwrap();
        let message = TemplateMessage {
            from: self.from.as_str(),
            to: addr,
            subject: sub,
            template: tmpl,
            variables: Some(&vars),
        };

        self.send(&message).await
    }

    #[inline]
    async fn send<T>(&self, form: &T) -> Result<()>
    where
        T: Serialize,
    {
        let path = format!("{}/messages", self.domain);
        let res = self
            .client
            .post(self.base.join(&path).unwrap())
            .basic_auth("api", Some(&self.api_key))
            .form(form)
            .send()
            .await?;

        res.error_for_status()?;

        Ok(())
    }
}

pub fn with_mail(mail: Client) -> impl Filter<Extract = (Client,), Error = Infallible> + Clone {
    warp::any().map(move || mail.clone())
}
