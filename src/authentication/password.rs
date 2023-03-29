use crate::{error, http::HttpClient, model::Status, AppState, Result};

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};

use axum::extract::FromRef;
use http::StatusCode;
use passwords::{analyzer, scorer};
use rand::rngs::OsRng;
use reqwest::Url;
use sha1::{Digest, Sha1};
use tracing::error;

/// Minimum password score
const SCORE_MIN: f64 = 85.0;

#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("password does not match")]
    Mismatch,
    #[error("password is invalid: {0}")]
    Invalid(String),
    #[error("password is too weak")]
    BadScore,
    #[error("password has been pwned (compromised), {0} times")]
    Pwned(u64),
    #[error("password hash error: {0}")]
    Hash(#[from] argon2::password_hash::Error),
}

impl error::ErrorResponse for PasswordError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        match self {
            PasswordError::Mismatch => StatusCode::UNAUTHORIZED,
            PasswordError::Invalid(_) | PasswordError::BadScore | PasswordError::Pwned(_) => {
                StatusCode::BAD_REQUEST
            }
            PasswordError::Hash(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> Self::Response {
        let msg = match self.status_code() {
            StatusCode::INTERNAL_SERVER_ERROR => {
                error!(error = %self, "internal error");
                "internal server error".to_string()
            }
            _ => self.to_string(),
        };

        Status::new(self.status_code(), msg)
    }
}

#[derive(Clone)]
pub struct Password {
    hasher: Hasher,
    hibp: Hibp,
    hibp_check: bool,
}

impl Password {
    pub fn new(hasher: Hasher, hibp: Hibp, hibp_check: bool) -> Self {
        Self {
            hasher,
            hibp,
            hibp_check,
        }
    }

    pub async fn validate_and_hash<P: AsRef<str>>(&self, password: P) -> Result<String> {
        self.validate_password(password.as_ref())?;

        if self.hibp_check {
            self.hibp.check_password(password.as_ref()).await?;
        }

        let hash = self.hasher.hash_password(password.as_ref())?;

        Ok(hash)
    }

    pub fn verify<P, H>(&self, password: P, hash: H) -> Result<()>
    where
        P: AsRef<[u8]>,
        H: AsRef<str>,
    {
        self.hasher.verify_password(password, hash)
    }

    fn validate_password(&self, password: &str) -> Result<()> {
        if !password.is_ascii() {
            return Err(
                PasswordError::Invalid("password has invalid characters".to_string()).into(),
            );
        }

        let analysis = analyzer::analyze(password);

        if analysis.length() < 16 {
            return Err(PasswordError::Invalid(
                "password must have at least 16 characters".to_string(),
            )
            .into());
        }
        if analysis.length() > 80 {
            return Err(
                PasswordError::Invalid("password cannot exceed 80 characters".to_string()).into(),
            );
        }
        if analysis.uppercase_letters_count() < 1 {
            return Err(PasswordError::Invalid(
                "password must have at least one uppercase character".to_string(),
            )
            .into());
        }
        if analysis.lowercase_letters_count() < 1 {
            return Err(PasswordError::Invalid(
                "password must have at least one lowercase character".to_string(),
            )
            .into());
        }
        if analysis.lowercase_letters_count() < 1 {
            return Err(PasswordError::Invalid(
                "password must have at least one lowercase character".to_string(),
            )
            .into());
        }
        if analysis.numbers_count() < 1 {
            return Err(PasswordError::Invalid(
                "password must have at least one digit".to_string(),
            )
            .into());
        }

        if scorer::score(&analysis) < SCORE_MIN {
            return Err(PasswordError::BadScore.into());
        }

        Ok(())
    }
}

impl FromRef<AppState> for Password {
    fn from_ref(state: &AppState) -> Self {
        state.password.clone()
    }
}

#[derive(Clone)]
#[non_exhaustive]
pub struct Hasher {
    context: Argon2<'static>,
}

impl Hasher {
    const ALGO: Algorithm = Algorithm::Argon2id;
    const VERSION: Version = Version::V0x13;
    const M_COST: u32 = 19 * 1024;
    const T_COST: u32 = 2;
    const P_COST: u32 = 1;
    const OUTPUT_LEN: usize = Params::DEFAULT_OUTPUT_LEN;

    #[inline]
    pub fn hash_password<P: AsRef<[u8]>>(&self, password: P) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let hash = self
            .context
            .hash_password(password.as_ref(), &salt)
            .map_err(PasswordError::from)?;

        Ok(hash.to_string())
    }

    #[inline]
    pub fn verify_password<P, H>(&self, password: P, hash: H) -> Result<()>
    where
        P: AsRef<[u8]>,
        H: AsRef<str>,
    {
        let hash = PasswordHash::new(hash.as_ref()).map_err(PasswordError::from)?;
        if let Err(err) = self.context.verify_password(password.as_ref(), &hash) {
            match err {
                argon2::password_hash::Error::Password => {
                    return Err(PasswordError::Mismatch.into())
                }
                _ => return Err(PasswordError::Hash(err).into()),
            }
        }

        Ok(())
    }
}

impl Default for Hasher {
    fn default() -> Self {
        let params = Params::new(
            Self::M_COST,
            Self::T_COST,
            Self::P_COST,
            Some(Self::OUTPUT_LEN),
        )
        .unwrap();
        let argon2 = Argon2::new(Self::ALGO, Self::VERSION, params);

        Self { context: argon2 }
    }
}

#[derive(Clone, Default)]
#[non_exhaustive]
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
            return Err(PasswordError::Pwned(n).into());
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
