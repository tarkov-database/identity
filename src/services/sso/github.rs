use crate::{
    auth::token::{sign::TokenSigner, verify::TokenVerifier},
    config::GlobalConfig,
    database::Collection,
    http::HttpClient,
    services::{
        error::ErrorResponse,
        model::{Response, Status},
        session::{SessionClaims, SessionResponse},
        user::{
            model::{Connection, SessionDocument, UserDocument},
            UserError,
        },
        ServiceResult,
    },
    services::{extract::Query, model::EmailAddr},
    state::AppState,
};

use super::{oauth::StateClaims, SsoError};

use axum::{
    extract::{FromRef, State, TypedHeader},
    response::{IntoResponse, Redirect},
};

use chrono::Utc;
use headers::{Cookie, HeaderMap, HeaderValue};
use http::{
    header::{ACCEPT, AUTHORIZATION, SET_COOKIE},
    StatusCode,
};
use hyper::Uri;
use mongodb::bson::{doc, oid::ObjectId};
use reqwest::IntoUrl;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use url::Url;

#[derive(Debug, Deserialize)]
#[serde(
    rename_all = "snake_case",
    tag = "error",
    content = "error_description"
)]
pub enum TokenAccessError {
    BadVerificationCode(String),
    RedirectUriMismatch(String),
    IncorrectClientCredentials(String),
}

impl std::fmt::Display for TokenAccessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenAccessError::BadVerificationCode(e) => {
                write!(f, "bad verification code: {}", e)
            }
            TokenAccessError::RedirectUriMismatch(e) => {
                write!(f, "redirect uri mismatch: {}", e)
            }
            TokenAccessError::IncorrectClientCredentials(e) => {
                write!(f, "incorrect client credentials: {}", e)
            }
        }
    }
}

impl std::error::Error for TokenAccessError {}

impl ErrorResponse for TokenAccessError {
    type Response = Status;

    fn status_code(&self) -> StatusCode {
        match self {
            TokenAccessError::BadVerificationCode(_) | TokenAccessError::RedirectUriMismatch(_) => {
                StatusCode::UNAUTHORIZED
            }
            TokenAccessError::IncorrectClientCredentials(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> Self::Response {
        Status::new(self.status_code(), self.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct GitHub {
    client_id: String,
    client_secret: String,
    redirect_uri: Url,
    client: HttpClient,
}

impl GitHub {
    pub fn new<U>(
        client_id: String,
        client_secret: String,
        redirect: U,
        client: HttpClient,
    ) -> Result<Self, reqwest::Error>
    where
        U: IntoUrl,
    {
        Ok(Self {
            client_id,
            client_secret,
            redirect_uri: redirect.into_url()?,
            client,
        })
    }

    async fn get_access_token(&self, code: &str) -> Result<TokenResponse, SsoError> {
        let url = Url::parse("https://github.com/login/oauth/access_token").unwrap();
        let form = TokenRequest {
            client_id: &self.client_id,
            client_secret: &self.client_secret,
            code,
            redirect_uri: &self.redirect_uri,
        };

        let res = self
            .client
            .post(url)
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .form(&form)
            .send()
            .await?;

        let body = if res.status().is_success() {
            res.json().await?
        } else {
            return Err(res.json::<TokenAccessError>().await?)?;
        };

        Ok(body)
    }

    async fn get_current_user(&self, access_token: &str) -> Result<User, SsoError> {
        let path = "/user";
        let res = self.api_get(path, access_token).await?;

        Ok(res)
    }

    async fn get_emails(&self, access_token: &str) -> Result<Vec<Email>, SsoError> {
        let path = "/user/emails";
        let res = self.api_get(path, access_token).await?;

        Ok(res)
    }

    #[inline]
    async fn api_get<T>(&self, path: &str, access_token: &str) -> Result<T, SsoError>
    where
        T: DeserializeOwned,
    {
        let url = Url::parse("https://api.github.com")
            .unwrap()
            .join(path)
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github.v3+json"),
        );
        headers.insert(
            AUTHORIZATION,
            format!("token {}", access_token).parse().unwrap(),
        );

        let res = self.client.get(url).headers(headers).send().await?;
        let body = res.error_for_status()?.json().await?;

        Ok(body)
    }
}

impl FromRef<AppState> for GitHub {
    fn from_ref(state: &AppState) -> Self {
        state.github_client.clone()
    }
}

#[derive(Debug, Serialize)]
struct TokenRequest<'a> {
    client_id: &'a str,
    client_secret: &'a str,
    code: &'a str,
    redirect_uri: &'a Url,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum TokenType {
    Bearer,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: TokenType,
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct User {
    login: String,
    id: i64,
    // node_id: String,
    // avatar_url: Url,
    // gravatar_id: String,
    // url: Url,
    // html_url: Url,
    // followers_url: Url,
    // following_url: Url,
    // gists_url: Url,
    // starred_url: Url,
    // subscriptions_url: Url,
    // organizations_url: Url,
    // repos_url: Url,
    // events_url: Url,
    // received_events_url: Url,
    // r#type: String,
    // site_admin: bool,
    // name: String,
    // company: String,
    // blog: String,
    // location: String,
    // email: String,
    // hireable: bool,
    // bio: String,
    // twitter_username: String,
    // public_repos: i64,
    // public_gists: i64,
    // followers: i64,
    // following: i64,
    // created_at: String,
    // updated_at: String,
    // private_gists: i64,
    // total_private_repos: i64,
    // owned_private_repos: i64,
    // disk_usage: i64,
    // collaborators: i64,
    two_factor_authentication: bool,
}

#[derive(Debug, Deserialize)]
struct Email {
    #[serde(rename = "email")]
    address: EmailAddr,
    verified: bool,
    primary: bool,
    visibility: Option<String>,
}

pub(super) async fn authorize(
    State(gh): State<GitHub>,
    State(signer): State<TokenSigner>,
) -> ServiceResult<axum::response::Response> {
    let claims = StateClaims::new();
    let state = signer.sign(&claims).await?;

    let pq = format!(
        "/login/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&state={state}",
        client_id = gh.client_id,
        redirect_uri = gh.redirect_uri,
        scope = ["read:user", "user:email"].join("%20"),
        state = state,
    );

    let uri = Uri::builder()
        .scheme("https")
        .authority("github.com")
        .path_and_query(pq)
        .build()
        .unwrap();

    let mut redirect = Redirect::to(&uri.to_string()).into_response();
    let cookie = format!(
        "state={}; Path=/v1/sso/github; Max-Age={}; SameSite=Lax; Secure; HttpOnly",
        state,
        StateClaims::DEFAULT_EXP_MIN * 60,
    )
    .parse()
    .unwrap();
    redirect.headers_mut().insert(SET_COOKIE, cookie);

    Ok(redirect)
}

#[derive(Debug, Deserialize)]
pub struct AuthorizedParams {
    code: String,
    state: String,
}

pub(super) async fn authorized(
    Query(params): Query<AuthorizedParams>,
    TypedHeader(cookies): TypedHeader<Cookie>,
    State(github): State<GitHub>,
    State(users): State<Collection<UserDocument>>,
    State(global): State<GlobalConfig>,
    State(signer): State<TokenSigner>,
    State(verifier): State<TokenVerifier>,
) -> ServiceResult<Response<SessionResponse>> {
    let state = cookies.get("state").ok_or(SsoError::StateMissing)?;

    if state != params.state {
        return Err(SsoError::InvalidState)?;
    }

    let _claims = verifier
        .verify::<StateClaims>(state)
        .await
        .map_err(|_| SsoError::InvalidState)?;

    let TokenResponse { access_token, .. } = github.get_access_token(&params.code).await?;

    let (user, emails) = tokio::try_join!(
        github.get_current_user(&access_token),
        github.get_emails(&access_token)
    )?;

    let email = emails
        .into_iter()
        .find(|e| e.primary && e.verified)
        .ok_or(SsoError::EmailInvalid)?;

    let connection = Connection::GitHub {
        user_id: user.id,
        login: user.login,
        two_factor_enabled: user.two_factor_authentication,
    };

    let query = doc! {"$or": [
        {"connections": { "$elemMatch": { "type": "github", "userId": user.id } }},
        {"email": &email.address },
    ]};

    let user = match users.get_one(query, None).await? {
        Some(doc) => {
            if let Some(c) = doc.connections.iter().find(|&c| c.is_github()) {
                if c != &connection {
                    users.update_connection(doc.id, connection).await?
                } else {
                    doc
                }
            } else {
                users.insert_connection(doc.id, connection).await?
            }
        }
        None => {
            if !global.is_allowed_domain(email.address.domain()) {
                return Err(UserError::DomainNotAllowed)?;
            }

            let doc = UserDocument {
                id: ObjectId::new(),
                email: email.address,
                password: None,
                can_login: true,
                verified: true,
                locked: false,
                roles: Default::default(),
                sessions: Default::default(),
                connections: vec![connection],
                last_modified: Utc::now(),
                created: Utc::now(),
            };

            users.insert(&doc).await?;

            doc
        }
    };

    let session = SessionDocument::new();

    let claims = SessionClaims::new(session.id, user.id);
    let token = signer.sign(&claims).await?;

    let response = SessionResponse {
        user_id: user.id.to_hex(),
        token,
        expires_at: claims.exp,
    };

    users.set_session(user.id, session).await?;

    Ok(Response::with_status(StatusCode::CREATED, response))
}
