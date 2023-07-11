mod handler;
mod routes;

use std::iter;

use crate::{
    auth::token::{Token, TokenType, TokenValidation, LEEWAY},
    error,
    model::Status,
    user,
};

use chrono::{serde::ts_seconds, DateTime, Duration, Utc};
use hyper::StatusCode;
use serde::{Deserialize, Serialize};

pub use routes::routes;

#[derive(Debug, thiserror::Error)]
pub enum TokenError {}

impl error::ErrorResponse for TokenError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }

    fn error_response(&self) -> Self::Response {
        Status::new(self.status_code(), self.to_string())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessClaims<S = String> {
    pub aud: Vec<String>,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub nbf: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,
    pub sub: String,
    pub scope: Vec<S>,
}

impl<S> AccessClaims<S> {
    pub const DEFAULT_EXP_MIN: i64 = 30;

    fn new<A>(aud: A, sub: &str) -> Self
    where
        A: IntoIterator,
        A::Item: ToString,
    {
        Self {
            aud: aud.into_iter().map(|a| a.to_string()).collect(),
            exp: Utc::now() + Duration::minutes(Self::DEFAULT_EXP_MIN),
            nbf: Utc::now(),
            iat: Utc::now(),
            sub: sub.into(),
            scope: Vec::default(),
        }
    }

    fn with_scope<A, I>(aud: A, sub: &str, scope: I) -> Self
    where
        A: IntoIterator,
        A::Item: ToString,
        I: IntoIterator<Item = S>,
    {
        let mut claims = Self::new(aud, sub);
        claims.scope = scope.into_iter().collect();

        claims
    }
}

impl AccessClaims<Scope> {
    const AUDIENCE: &str = "identity/resource";

    fn with_roles<R>(user_id: &str, roles: R) -> Self
    where
        R: IntoIterator<Item = user::Role>,
    {
        let scope = Scope::from_roles(roles);
        Self::with_scope(iter::once(Self::AUDIENCE), user_id, scope)
    }
}

impl<S> Token for AccessClaims<S>
where
    S: Serialize + for<'de> Deserialize<'de>,
{
    const TYPE: TokenType = TokenType::Access;

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

impl TokenValidation for AccessClaims<Scope> {
    fn validation(alg: jsonwebtoken::Algorithm) -> jsonwebtoken::Validation {
        let mut validation = jsonwebtoken::Validation::new(alg);
        validation.leeway = LEEWAY;
        validation.set_required_spec_claims(&["exp", "nbf", "sub", "aud", "iat"]);
        validation.set_audience(&[Self::AUDIENCE]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Scope {
    UserRead,
    UserWrite,

    ClientRead,
    ClientWrite,

    ServiceRead,
    ServiceWrite,
}

impl Scope {
    pub fn from_roles<R>(roles: R) -> Vec<Scope>
    where
        R: IntoIterator<Item = user::Role>,
    {
        let mut scope = roles
            .into_iter()
            .map(Into::into)
            .collect::<Vec<Vec<Scope>>>()
            .concat::<Scope>();

        scope.dedup();
        scope.sort_unstable();

        scope
    }
}

impl From<user::Role> for Vec<Scope> {
    fn from(role: user::Role) -> Self {
        match role {
            user::Role::UserEditor => vec![Scope::UserRead, Scope::UserWrite],
            user::Role::UserViewer => vec![Scope::UserRead],
            user::Role::ClientEditor => vec![Scope::ClientRead, Scope::ClientWrite],
            user::Role::ClientViewer => vec![Scope::ClientRead],
            user::Role::ServiceEditor => vec![Scope::ServiceRead, Scope::ServiceWrite],
            user::Role::ServiceViewer => vec![Scope::ServiceRead],
        }
    }
}
