use jsonwebtoken::{
    errors::{Error as JwtError, ErrorKind},
    DecodingKey, EncodingKey, Validation,
};
use serde::{Deserialize, Serialize};
use tracing::error;

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
                error!("{:?}", error);
                Self::Invalid
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TokenType {
    Session,
    Client,
    Service,
    Action,
}

#[derive(Debug, Clone)]
pub struct TokenConfig {
    pub enc_key: EncodingKey,
    pub dec_key: DecodingKey<'static>,
    pub validation: Validation,
    pub r#type: Option<TokenType>,
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
            enc_key: EncodingKey::from_secret(secret.as_ref()),
            dec_key: DecodingKey::from_secret(secret.as_ref()).into_static(),
            validation,
            r#type: None,
        }
    }

    pub fn set_type(&mut self, r#type: Option<TokenType>) {
        self.r#type = r#type;
    }
}
