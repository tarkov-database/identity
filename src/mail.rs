use crate::{http::HttpClient, state::AppState, Result};

use std::collections::HashMap;

use axum::extract::FromRef;
use reqwest::Url;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Deserialize)]
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
    client: HttpClient,
}

impl Client {
    pub fn new(
        api_key: String,
        region: Region,
        domain: String,
        from: String,
        client: HttpClient,
    ) -> Result<Self> {
        let base = region.base_url().join("v3/").unwrap();

        Ok(Self {
            from,
            base,
            api_key,
            domain,
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
        vars: HashMap<&str, &str>,
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

impl FromRef<AppState> for Client {
    fn from_ref(state: &AppState) -> Self {
        state.mail_client.clone()
    }
}
