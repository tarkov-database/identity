pub mod hibp;

use crate::{services::error::ErrorResponse, services::model::Status, state::AppState};

use self::hibp::HibpClient;

use argon2::Argon2;
use axum::extract::FromRef;
use http::StatusCode;
use passwords::{analyzer, scorer};
use tracing::error;

/// Minimum password score
const SCORE_MIN: f64 = 85.0;

#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    #[error("password does not match")]
    Mismatch,

    #[error("password is invalid: {0}")]
    Invalid(&'static str),

    #[error("password is too weak")]
    BadScore,

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
            PasswordError::Invalid(_) | PasswordError::BadScore | PasswordError::Compromised(_) => {
                StatusCode::BAD_REQUEST
            }
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
        if !password.as_ref().is_ascii() {
            return Err(PasswordError::Invalid("password has invalid characters"));
        }

        let analysis = analyzer::analyze(&password);

        if analysis.length() < 16 {
            return Err(PasswordError::Invalid(
                "password must have at least 16 characters",
            ));
        }
        if analysis.length() > 80 {
            return Err(PasswordError::Invalid(
                "password cannot exceed 80 characters",
            ));
        }
        if analysis.uppercase_letters_count() < 1 {
            return Err(PasswordError::Invalid(
                "password must have at least one uppercase character",
            ));
        }
        if analysis.lowercase_letters_count() < 1 {
            return Err(PasswordError::Invalid(
                "password must have at least one lowercase character",
            ));
        }
        if analysis.lowercase_letters_count() < 1 {
            return Err(PasswordError::Invalid(
                "password must have at least one lowercase character",
            ));
        }
        if analysis.numbers_count() < 1 {
            return Err(PasswordError::Invalid(
                "password must have at least one digit",
            ));
        }

        if scorer::score(&analysis) < SCORE_MIN {
            return Err(PasswordError::BadScore);
        }

        if self.hibp_check {
            if let Some(count) = self
                .hibp
                .check_password(password.as_ref().as_bytes())
                .await?
            {
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
