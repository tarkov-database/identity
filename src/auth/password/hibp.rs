use crate::http::HttpClient;

use reqwest::Url;
use sha1::{Digest, Sha1};

#[derive(Debug, thiserror::Error)]
pub enum HibpError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
}

#[derive(Clone, Default)]
#[non_exhaustive]
pub struct HibpClient {
    client: HttpClient,
}

impl HibpClient {
    const PASSWORD_API_URL: &'static str = "https://api.pwnedpasswords.com";

    pub fn with_client(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn check_password(
        &self,
        password: impl AsRef<[u8]>,
    ) -> Result<Option<u64>, HibpError> {
        let hash = format!("{:x}", Sha1::digest(password)).to_uppercase();

        self.find_hash(&hash).await
    }

    async fn find_hash(&self, hash: &str) -> Result<Option<u64>, HibpError> {
        let url = format!("{}/range/{}", Self::PASSWORD_API_URL, &hash[..5])
            .parse::<Url>()
            .unwrap();

        let hashes = self
            .client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        let result = hashes.lines().find(|s| s[..35] == hash[5..]).map(|s| {
            let (_, count) = s.split_once(':').unwrap();
            count.parse().unwrap()
        });

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PWNED_PASSWORD: &str = "foobar";

    #[tokio::test]
    async fn hibp_password_check() {
        let hibp = HibpClient::default();
        let count = hibp.check_password(PWNED_PASSWORD).await.unwrap().unwrap();
        assert!(count > 0);
    }
}
