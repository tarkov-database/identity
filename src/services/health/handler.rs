use crate::{
    health::{SharedStatus, State as HealthState},
    services::{model::Response, ServiceResult},
};

use axum::extract::State;
use chrono::{serde::ts_seconds, DateTime, Utc};
use hyper::StatusCode;
use mongodb::bson::doc;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    state: HealthState,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(with = "ts_seconds")]
    last_changed: DateTime<Utc>,
}

pub async fn get(State(status): State<SharedStatus>) -> ServiceResult<Response<HealthResponse>> {
    let status = status.get().await;

    let body = HealthResponse {
        state: status.state,
        message: None,
        last_changed: status.last_update.into(),
    };

    let status = match status.state {
        HealthState::Up => StatusCode::OK,
        HealthState::Degraded => StatusCode::OK,
        HealthState::Down => StatusCode::SERVICE_UNAVAILABLE,
    };

    Ok(Response::with_status(status, body))
}
