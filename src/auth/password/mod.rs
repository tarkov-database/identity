pub mod hibp;

use crate::{services::error::ErrorResponse, services::model::Status, state::AppState};

use self::hibp::HibpClient;

use argon2::Argon2;
use axum::extract::FromRef;
use http::StatusCode;
use tracing::error;

#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("password does not match")]
    Mismatch,

    #[error("password is invalid: {0}")]
    Invalid(&'static str),

    #[error("password has been compromised, {0} times")]
    Compromised(u64),

    #[error("password hasher error: {0}")]
    Hash(#[from] password_hash::Error),

    #[error("hibp error: {0}")]
    Hibp(#[from] hibp::HibpError),
}

impl ErrorResponse for PasswordError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        match self {
            PasswordError::Mismatch => StatusCode::UNAUTHORIZED,
            PasswordError::Invalid(_) | PasswordError::Compromised(_) => StatusCode::BAD_REQUEST,
            PasswordError::Hash(_) | PasswordError::Hibp(_) => StatusCode::INTERNAL_SERVER_ERROR,
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

impl axum::response::IntoResponse for PasswordError {
    fn into_response(self) -> axum::response::Response {
        self.error_response().into_response()
    }
}

pub type PasswordHasher = crate::crypto::hash::PasswordHasher<Argon2<'static>>;

impl FromRef<AppState> for PasswordHasher {
    fn from_ref(state: &AppState) -> Self {
        state.password_hasher.clone()
    }
}

#[derive(Clone)]
pub struct PasswordValidator {
    hibp: HibpClient,
    hibp_check: bool,
}

impl PasswordValidator {
    pub fn new(hibp: HibpClient, hibp_check: bool) -> Self {
        Self { hibp, hibp_check }
    }

    pub async fn validate(&self, password: impl AsRef<str>) -> Result<(), PasswordError> {
        let password = password.as_ref();
        let length = password.len();

        if length < 16 {
            return Err(PasswordError::Invalid(
                "password must be at least 16 characters",
            ));
        }
        if length > 32 {
            return Err(PasswordError::Invalid(
                "password must be at most 32 characters",
            ));
        }

        if !password.is_ascii() {
            return Err(PasswordError::Invalid("password has invalid characters"));
        }

        let (lower, upper, digit, _symbol) =
            password
                .chars()
                .fold((0, 0, 0, 0), |(lower, upper, digit, symbol), c| {
                    if c.is_ascii_lowercase() {
                        (lower + 1, upper, digit, symbol)
                    } else if c.is_ascii_uppercase() {
                        (lower, upper + 1, digit, symbol)
                    } else if c.is_ascii_digit() {
                        (lower, upper, digit + 1, symbol)
                    } else {
                        (lower, upper, digit, symbol + 1)
                    }
                });

        if lower < 1 {
            return Err(PasswordError::Invalid(
                "password must contain at least 1 lowercase character",
            ));
        }
        if upper < 1 {
            return Err(PasswordError::Invalid(
                "password must contain at least 1 uppercase character",
            ));
        }
        if digit < 1 {
            return Err(PasswordError::Invalid(
                "password must contain at least 1 digit",
            ));
        }

        if self.hibp_check {
            if let Some(count) = self.hibp.check_password(password).await? {
                return Err(PasswordError::Compromised(count));
            }
        }

        Ok(())
    }
}

impl FromRef<AppState> for PasswordValidator {
    fn from_ref(state: &AppState) -> Self {
        state.password_validator.clone()
    }
}
