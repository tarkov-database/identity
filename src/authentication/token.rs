use crate::{error, model::Status};

use hyper::StatusCode;
use jsonwebtoken::{
    errors::{Error as JwtError, ErrorKind},
    Algorithm, DecodingKey, EncodingKey, Validation,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::error;

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("token is expired")]
    Expired,
    #[error("token is not yet valid")]
    Immature,
    #[error("token has wrong type")]
    WrongType,
    #[error("token is invalid")]
    Invalid,
    #[error("Token could not be encoded: {0}")]
    EncodingFailed(JwtError),
}

impl From<JwtError> for TokenError {
    fn from(error: JwtError) -> Self {
        match *error.kind() {
            ErrorKind::ExpiredSignature => Self::Expired,
            ErrorKind::ImmatureSignature => Self::Immature,
            _ => {
                error!("{:?}", error);
                Self::Invalid
            }
        }
    }
}

impl error::ErrorResponse for TokenError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        match self {
            TokenError::Expired => StatusCode::UNAUTHORIZED,
            TokenError::Immature => StatusCode::UNAUTHORIZED,
            TokenError::WrongType => StatusCode::UNAUTHORIZED,
            TokenError::Invalid => StatusCode::UNAUTHORIZED,
            TokenError::EncodingFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> Self::Response {
        Status::new(self.status_code(), self.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TokenType {
    Session,
    Client,
    Action,
}

pub trait TokenClaims
where
    Self: Serialize + DeserializeOwned + Sized,
{
    const TOKEN_TYPE: TokenType;

    fn get_type(&self) -> &TokenType;

    fn encode(&self, config: &TokenConfig) -> Result<String, TokenError> {
        let header = jsonwebtoken::Header::new(config.alg);
        let token = jsonwebtoken::encode(&header, self, &config.enc_key).map_err(|e| {
            error!("Error while encoding token: {:?}", e);
            TokenError::EncodingFailed(e)
        })?;

        Ok(token)
    }
}

#[derive(Debug, Clone)]
pub struct TokenConfig {
    pub alg: Algorithm,
    pub enc_key: EncodingKey,
    pub dec_key: DecodingKey<'static>,
    pub validation: Validation,
}

impl TokenConfig {
    const LEEWAY: u64 = 10;

    pub fn from_secret<S, A, T>(secret: S, audience: A) -> Self
    where
        S: AsRef<[u8]>,
        A: AsRef<[T]>,
        T: ToString,
    {
        let mut validation = Validation {
            leeway: Self::LEEWAY,
            ..Validation::default()
        };
        validation.set_audience(audience.as_ref());

        Self {
            alg: Algorithm::HS256,
            enc_key: EncodingKey::from_secret(secret.as_ref()),
            dec_key: DecodingKey::from_secret(secret.as_ref()).into_static(),
            validation,
        }
    }
}
