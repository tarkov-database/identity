pub mod sign;
pub mod verify;

use crate::{services::error::ErrorResponse, services::model::Status};

use std::str::FromStr;

use base64ct::{Base64, Encoding};
use chrono::{DateTime, Utc};
use hyper::StatusCode;
use jsonwebtoken::{
    errors::{Error as JwtError, ErrorKind},
    Algorithm, Header, Validation,
};
use pki_rs::certificate::{Certificate, CertificateChain};
use serde::{Deserialize, Serialize};
use tracing::error;

/// Leeway for token validation in seconds.
/// This is used to account for clock skew.
pub const LEEWAY: u64 = 30;

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("token is expired")]
    Expired,
    #[error("token is not yet valid")]
    Immature,
    #[error("token is invalid")]
    Invalid,
    #[error("token exceeds certificate lifetime")]
    CertLifetimeExceeded,

    #[error("pki error: {0}")]
    Pki(#[from] pki_rs::error::Error),
    #[error("token could not be encoded: {0}")]
    Encoding(JwtError),
}

impl From<JwtError> for TokenError {
    fn from(error: JwtError) -> Self {
        match *error.kind() {
            ErrorKind::ExpiredSignature => Self::Expired,
            ErrorKind::ImmatureSignature => Self::Immature,
            _ => {
                error!(error = %error, "jsonwebtoken error");
                Self::Invalid
            }
        }
    }
}

impl ErrorResponse for TokenError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        match self {
            TokenError::Expired | TokenError::Immature | TokenError::Invalid => {
                StatusCode::UNAUTHORIZED
            }
            TokenError::CertLifetimeExceeded | TokenError::Encoding(_) | TokenError::Pki(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
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

impl axum::response::IntoResponse for TokenError {
    fn into_response(self) -> axum::response::Response {
        self.error_response().into_response()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TokenType {
    Session,
    Refresh,
    Access,
    Action,
    State,
}

impl TokenType {
    /// Returns the token type as a string.
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Session => "session",
            Self::Refresh => "refresh",
            Self::Access => "access",
            Self::Action => "action",
            Self::State => "state",
        }
    }
}

impl ToString for TokenType {
    fn to_string(&self) -> String {
        self.as_str().to_string()
    }
}

#[derive(Debug)]
pub struct ParseTokenTypeError;

impl FromStr for TokenType {
    type Err = ParseTokenTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = match s {
            v if v == Self::Session.as_str() => Self::Session,
            v if v == Self::Refresh.as_str() => Self::Refresh,
            v if v == Self::Access.as_str() => Self::Access,
            v if v == Self::Action.as_str() => Self::Action,
            v if v == Self::State.as_str() => Self::State,
            _ => return Err(ParseTokenTypeError),
        };

        Ok(value)
    }
}

pub trait Token {
    const TYPE: TokenType;

    fn issued_at(&self) -> DateTime<Utc>;

    fn expires_at(&self) -> DateTime<Utc>;

    fn not_before(&self) -> DateTime<Utc>;
}

pub trait TokenValidation {
    fn validation(alg: Algorithm) -> Validation;
}

pub trait HeaderExt {
    fn token_type(&self) -> Result<TokenType, TokenError>;

    fn get_certificates(&self) -> Result<Option<CertificateChain>, TokenError>;

    // fn set_certificates(&mut self, certs: &CertificateChain) -> Result<(), TokenError>;
}

impl HeaderExt for Header {
    fn token_type(&self) -> Result<TokenType, TokenError> {
        let t = self
            .typ
            .as_deref()
            .ok_or(TokenError::Invalid)?
            .parse::<TokenType>()
            .map_err(|_| TokenError::Invalid)?;

        Ok(t)
    }

    fn get_certificates(&self) -> Result<Option<CertificateChain>, TokenError> {
        if let Some(v) = self.x5c.as_ref() {
            let mut certs_iter = v.iter().map(|cert| {
                let asn1 = Base64::decode_vec(cert).map_err(|_| TokenError::Invalid)?;
                Certificate::from_der(asn1).map_err(|_| TokenError::Invalid)
            });

            let leaf = match certs_iter.next() {
                Some(Ok(cert)) => cert,
                Some(Err(err)) => return Err(err),
                None => return Ok(None),
            };

            let intermediates = certs_iter.collect::<Result<Vec<_>, _>>()?;
            let chain = CertificateChain::new(intermediates, leaf);

            Ok(Some(chain))
        } else {
            Ok(None)
        }
    }

    // fn set_certificates(&mut self, certs: &CertificateChain) -> Result<(), TokenError> {
    //     let certs_encoded = certs
    //         .iter()
    //         .rev()
    //         .map(|cert| {
    //             let cert = cert.to_der().map_err(|_| TokenError::Invalid)?;
    //             let cert = Base64::encode_string(&cert);
    //             Ok(cert)
    //         })
    //         .collect::<Result<Vec<String>, TokenError>>()?;

    //     self.x5c = Some(certs_encoded);
    //     self.x5t_s256 = Some(certs.leaf().fingerprint_base64()?);

    //     Ok(())
    // }
}
