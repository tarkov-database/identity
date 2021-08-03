mod filter;
mod handler;

use crate::{error, model::Status, user::Role};

use chrono::{serde::ts_seconds, DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use warp::hyper::StatusCode;

pub use filter::filters;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("credentials are wrong")]
    BadCredentials,
    #[error("not allowed: {0}")]
    NotAllowed(String),
}

impl warp::reject::Reject for SessionError {}

impl error::ErrorResponse for SessionError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        match self {
            SessionError::BadCredentials => StatusCode::UNAUTHORIZED,
            SessionError::NotAllowed(_) => StatusCode::FORBIDDEN,
        }
    }

    fn error_response(&self) -> Self::Response {
        Status::new(self.status_code(), self.to_string())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionClaims {
    pub aud: Vec<String>,
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub iat: DateTime<Utc>,
    pub sub: String,
    #[serde(default)]
    pub scope: Vec<Scope>,
}

impl SessionClaims {
    pub const DEFAULT_EXP_MIN: i64 = 30;

    fn new<A>(aud: A, sub: &str) -> Self
    where
        A: IntoIterator<Item = String>,
    {
        Self {
            aud: aud.into_iter().collect(),
            exp: Utc::now() + Duration::minutes(Self::DEFAULT_EXP_MIN),
            iat: Utc::now(),
            sub: sub.into(),
            scope: Vec::default(),
        }
    }

    fn with_scope<A, S>(aud: A, sub: &str, scope: S) -> Self
    where
        A: IntoIterator<Item = String>,
        S: IntoIterator<Item = Scope>,
    {
        let mut claims = Self::new(aud, sub);
        claims.scope = scope.into_iter().collect();

        claims
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Scope {
    UserRead,
    UserWrite,

    ClientRead,
    ClientWrite,

    ServiceRead,
    ServiceWrite,
}

impl Scope {
    fn from_roles<R>(roles: R) -> Vec<Scope>
    where
        R: IntoIterator<Item = Role>,
    {
        let mut scope = roles
            .into_iter()
            .map(|r| r.into())
            .collect::<Vec<Vec<Scope>>>()
            .concat::<Scope>();

        scope.sort_unstable();
        scope.dedup();

        scope
    }
}

impl From<Role> for Vec<Scope> {
    fn from(role: Role) -> Self {
        match role {
            Role::UserEditor => vec![Scope::UserRead, Scope::UserWrite],
            Role::UserViewer => vec![Scope::UserRead],
            Role::ClientEditor => vec![Scope::ClientRead, Scope::ClientWrite],
            Role::ClientViewer => vec![Scope::ClientRead],
            Role::ServiceEditor => vec![Scope::ServiceRead, Scope::ServiceWrite],
            Role::ServiceViewer => vec![Scope::ServiceRead],
        }
    }
}
