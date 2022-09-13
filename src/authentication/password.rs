use crate::{http::HttpClient, AppState, Result};

use super::AuthenticationError;

use argon2::{
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier, Result as A2Result, SaltString,
    },
    Algorithm, Argon2, Params, Version,
};
use axum::extract::FromRef;
use passwords::{analyzer, scorer};
use rand::rngs::OsRng;
use reqwest::Url;
use sha1::{Digest, Sha1};
use tracing::error;

/// Minimum password score
const SCORE_MIN: f64 = 85.0;

// Argon2 config
const ALGO: Algorithm = Algorithm::Argon2id;
const VERSION: Version = Version::V0x13;
const M_COST: u32 = 4 << 10;
const T_COST: u32 = 3;
const P_COST: u32 = 2;

#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("password is invalid: {0}")]
    InvalidPassword(String),
    #[error("password is too weak")]
    BadScore,
    #[error("password has been pwned (compromised), {0} times")]
    Pwned(u64),
}

pub fn hash_password<S: AsRef<[u8]>>(password: S) -> A2Result<String> {
    let salt = SaltString::generate(&mut OsRng);

    let params = Params::new(M_COST, T_COST, P_COST, None)?;

    let argon2 = Argon2::new(ALGO, VERSION, params);

    let hash = argon2.hash_password(password.as_ref(), salt.as_ref())?;

    Ok(hash.to_string())
}

pub fn verify_password<S, H>(password: S, hash: H) -> A2Result<()>
where
    S: AsRef<[u8]>,
    H: AsRef<str>,
{
    let params = Params::new(M_COST, T_COST, P_COST, None)?;

    let argon2 = Argon2::new(ALGO, VERSION, params);

    let parsed_hash = PasswordHash::new(hash.as_ref())?;

    argon2.verify_password(password.as_ref(), &parsed_hash)?;

    Ok(())
}

pub fn validate_password(password: &str) -> std::result::Result<(), PasswordError> {
    if !password.is_ascii() {
        return Err(PasswordError::InvalidPassword(
            "password has invalid characters".to_string(),
        ));
    }

    let analysis = analyzer::analyze(password);

    if analysis.length() < 16 {
        return Err(PasswordError::InvalidPassword(
            "password must have at least 16 characters".to_string(),
        ));
    }
    if analysis.length() > 80 {
        return Err(PasswordError::InvalidPassword(
            "password cannot exceed 80 characters".to_string(),
        ));
    }
    if analysis.uppercase_letters_count() < 1 {
        return Err(PasswordError::InvalidPassword(
            "password must have at least one uppercase character".to_string(),
        ));
    }
    if analysis.lowercase_letters_count() < 1 {
        return Err(PasswordError::InvalidPassword(
            "password must have at least one lowercase character".to_string(),
        ));
    }
    if analysis.lowercase_letters_count() < 1 {
        return Err(PasswordError::InvalidPassword(
            "password must have at least one lowercase character".to_string(),
        ));
    }
    if analysis.numbers_count() < 1 {
        return Err(PasswordError::InvalidPassword(
            "password must have at least one digit".to_string(),
        ));
    }

    if scorer::score(&analysis) < SCORE_MIN {
        return Err(PasswordError::BadScore);
    }

    Ok(())
}

pub fn validate_and_hash(password: &str) -> Result<String> {
    if let Err(e) = validate_password(password) {
        return Err(AuthenticationError::from(e).into());
    }

    let hash = match hash_password(password) {
        Ok(h) => h,
        Err(e) => {
            error!("Error while hashing password: {:?}", e);
            return Err(AuthenticationError::from(PasswordError::InvalidPassword(
                "bad input".to_string(),
            ))
            .into());
        }
    };

    Ok(hash)
}

#[derive(Clone, Default)]
pub struct Hibp {
    client: HttpClient,
}

impl Hibp {
    const PASSWORD_API_URL: &'static str = "https://api.pwnedpasswords.com";

    pub fn with_client(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn check_password<P>(&self, password: P) -> Result<()>
    where
        P: AsRef<[u8]>,
    {
        let hash = format!("{:x}", Sha1::digest(password)).to_uppercase();

        if let Some(n) = self.find_hash(&hash).await? {
            return Err(AuthenticationError::from(PasswordError::Pwned(n)).into());
        }

        Ok(())
    }

    async fn find_hash(&self, hash: &str) -> Result<Option<u64>> {
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

impl FromRef<AppState> for Hibp {
    fn from_ref(state: &AppState) -> Self {
        state.hibp_client.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PWNED_PASSWORD: &str = "foobar";

    #[tokio::test]
    async fn hibp_password_check() {
        let hibp = Hibp::default();
        hibp.check_password(PWNED_PASSWORD).await.unwrap_err();
    }
}
