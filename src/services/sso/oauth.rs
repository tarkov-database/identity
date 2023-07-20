use chrono::{serde::ts_seconds, DateTime, Utc};

use serde::{Deserialize, Serialize};

use crate::auth::token::{Token, TokenType, TokenValidation, LEEWAY};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateClaims {
    pub aud: String,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub nbf: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,
}

impl StateClaims {
    pub const AUDIENCE_STATE: &str = "identity/state";

    pub const DEFAULT_EXP_MIN: i64 = 60;

    pub(super) fn new() -> Self {
        Self {
            aud: Self::AUDIENCE_STATE.to_string(),
            exp: Utc::now() + chrono::Duration::minutes(Self::DEFAULT_EXP_MIN),
            nbf: Utc::now(),
            iat: Utc::now(),
        }
    }
}

impl Token for StateClaims {
    const TYPE: TokenType = TokenType::State;

    fn expires_at(&self) -> DateTime<Utc> {
        self.exp
    }

    fn not_before(&self) -> DateTime<Utc> {
        self.nbf
    }

    fn issued_at(&self) -> DateTime<Utc> {
        self.iat
    }
}

impl TokenValidation for StateClaims {
    fn validation(alg: jsonwebtoken::Algorithm) -> jsonwebtoken::Validation {
        let mut validation = jsonwebtoken::Validation::new(alg);
        validation.leeway = LEEWAY;
        validation.set_required_spec_claims(&["exp", "nbf", "aud", "iat"]);
        validation.set_audience(&[Self::AUDIENCE_STATE]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation
    }
}
