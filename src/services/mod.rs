pub mod action;
pub mod client;
pub mod error;
pub mod extract;
pub mod model;
pub mod oauth;
pub mod routes;
pub mod service;
pub mod session;
pub mod sso;
pub mod token;
pub mod user;

pub use routes::routes;

pub(super) type ServiceResult<T> = std::result::Result<T, error::Error>;
