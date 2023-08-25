use crate::{database::Database, state::AppState};

use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use axum::extract::FromRef;
use serde::Serialize;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Up,
    Degraded,
    Down,
}

#[derive(Debug, Clone)]
pub struct Status {
    pub state: State,
    pub last_update: SystemTime,
}

impl Status {
    pub fn is_up(&self) -> bool {
        self.state == State::Up
    }

    pub fn is_degraded(&self) -> bool {
        self.state == State::Degraded
    }

    pub fn is_down(&self) -> bool {
        self.state == State::Down
    }
}

#[derive(Clone)]
pub struct SharedStatus(Arc<RwLock<Status>>);

impl SharedStatus {
    pub async fn get(&self) -> Status {
        self.0.read().await.clone()
    }
}

impl FromRef<AppState> for SharedStatus {
    fn from_ref(state: &AppState) -> Self {
        state.health.clone()
    }
}

#[derive(Debug, Clone)]
pub struct HealthMonitor {
    interval: Duration,
    database: Database,
    latency_treshold: Duration,

    status: Arc<RwLock<Status>>,
}

impl HealthMonitor {
    pub fn new(interval: Duration, database: Database, latency_treshold: Duration) -> Self {
        Self {
            status: Arc::new(RwLock::new(Status {
                state: State::Down,
                last_update: SystemTime::now(),
            })),

            interval,
            database,
            latency_treshold,
        }
    }

    pub fn status_ref(&self) -> SharedStatus {
        SharedStatus(self.status.clone())
    }

    pub async fn watch(self) {
        loop {
            tracing::debug!("Checking health status");

            let new_state = match self.database.ping().await {
                Ok(latency) if latency < self.latency_treshold => State::Up,
                Ok(latency) if latency >= self.latency_treshold => State::Degraded,
                Err(_) => State::Down,
                _ => unreachable!(),
            };

            let changed = {
                let current_status = self.status.read().await;
                current_status.state != new_state
            };

            if changed {
                let mut status = self.status.write().await;
                match new_state {
                    State::Up => tracing::info!(
                        old_state = ?status.state,
                        "Health changed to normal state"
                    ),
                    State::Degraded => tracing::warn!(
                        old_state = ?status.state,
                        "Health state changed to DEGRADED"
                    ),
                    State::Down => tracing::error!(
                        old_state = ?status.state,
                        "Health state changed to DOWN"
                    ),
                }
                status.state = new_state;
                status.last_update = SystemTime::now();
            }

            tokio::time::sleep(self.interval).await;
        }
    }
}
