use crate::error::Error;

use super::AuthenticationError;

use std::convert::Infallible;

use jsonwebtoken::{
    decode,
    errors::{Error as JwtError, ErrorKind},
    DecodingKey, EncodingKey, Validation,
};
use warp::{Filter, Rejection};

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("token is expired")]
    Expired,
    #[error("token is not yet valid")]
    Immature,
    #[error("token is invalid")]
    Invalid,
}

impl From<JwtError> for TokenError {
    fn from(error: JwtError) -> Self {
        match *error.kind() {
            ErrorKind::ExpiredSignature => Self::Expired,
            ErrorKind::ImmatureSignature => Self::Immature,
            _ => {
                log::error!("{:?}", error);
                Self::Invalid
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct TokenConfig {
    pub enc_key: EncodingKey,
    pub dec_key: DecodingKey<'static>,
    pub validation: Validation,
}

impl TokenConfig {
    const LEEWAY: u64 = 10;

    pub fn from_secret<S, A>(secret: S, audience: A) -> Self
    where
        S: AsRef<[u8]>,
        A: Into<Vec<String>>,
    {
        let mut validation = Validation {
            leeway: Self::LEEWAY,
            ..Validation::default()
        };
        validation.set_audience(&audience.into());

        Self {
            enc_key: EncodingKey::from_secret(secret.as_ref()),
            dec_key: DecodingKey::from_secret(secret.as_ref()).into_static(),
            validation,
        }
    }
}

pub fn with_config(
    config: TokenConfig,
) -> impl Filter<Extract = (TokenConfig,), Error = Infallible> + Clone {
    warp::any().map(move || config.clone())
}

pub fn with_auth<T>(config: TokenConfig) -> impl Filter<Extract = (T,), Error = Rejection> + Clone
where
    T: serde::de::DeserializeOwned,
{
    warp::header::<String>("authorization")
        .map(move |header| (header, config.clone()))
        .and_then(auth_handler)
}

async fn auth_handler<T>(
    (header, config): (String, TokenConfig),
) -> std::result::Result<T, Rejection>
where
    T: serde::de::DeserializeOwned,
{
    let token = if header.starts_with("Bearer ") {
        header.strip_prefix("Bearer ").unwrap()
    } else {
        return Err(Error::from(AuthenticationError::InvalidHeader(
            "authorization header is invalid".to_string(),
        ))
        .into());
    };

    let data = match decode(token, &config.dec_key, &config.validation) {
        Ok(d) => d,
        Err(e) => return Err(Error::from(AuthenticationError::from(TokenError::from(e))).into()),
    };

    Ok(data.claims)
}
