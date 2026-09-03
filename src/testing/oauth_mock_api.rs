// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde_json::Value;
use tokio::sync::{oneshot, Notify};

use super::test_server::SpawnedServer;

/// Shared state for the in-process mock `/v1/oauth-tokens/:provider_key` API.
#[derive(Clone, Default)]
pub(crate) struct MockOAuthApiState {
    pub store: Arc<Mutex<HashMap<String, Value>>>,
    pub put_calls: Arc<Mutex<Vec<(String, Value)>>>,
    pub get_calls: Arc<Mutex<Vec<String>>>,
    put_notify: Arc<Notify>,
}

impl MockOAuthApiState {
    fn put_call_count(&self) -> usize {
        self.put_calls.lock().expect("put_calls lock").len()
    }

    pub fn get_call_count(&self) -> usize {
        self.get_calls.lock().expect("get_calls lock").len()
    }

    pub fn put_calls_snapshot(&self) -> Vec<(String, Value)> {
        self.put_calls.lock().expect("put_calls lock").clone()
    }

    pub async fn wait_for_puts(&self, expected: usize) {
        while self.put_call_count() < expected {
            self.put_notify.notified().await;
        }
    }
}

async fn handle_get_token(
    State(state): State<MockOAuthApiState>,
    Path(provider_key): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !auth.starts_with("Bearer ") {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthorized"})),
        )
            .into_response();
    }

    state
        .get_calls
        .lock()
        .expect("get_calls lock")
        .push(provider_key.clone());

    let store = state.store.lock().expect("store lock");
    if let Some(token) = store.get(&provider_key) {
        (StatusCode::OK, Json(token.clone())).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not_found"})),
        )
            .into_response()
    }
}

async fn handle_put_token(
    State(state): State<MockOAuthApiState>,
    Path(provider_key): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !auth.starts_with("Bearer ") {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    state
        .put_calls
        .lock()
        .expect("put_calls lock")
        .push((provider_key.clone(), body.clone()));
    state
        .store
        .lock()
        .expect("store lock")
        .insert(provider_key, body);
    state.put_notify.notify_waiters();

    StatusCode::OK.into_response()
}

/// Starts a mock OAuth token persistence API bound to `127.0.0.1:0`.
pub async fn start_mock_oauth_api() -> (String, MockOAuthApiState, oneshot::Sender<()>) {
    let state = MockOAuthApiState::default();
    let app = Router::new()
        .route(
            "/v1/oauth-tokens/:provider_key",
            get(handle_get_token).put(handle_put_token),
        )
        .with_state(state.clone());
    let server = SpawnedServer::bind(app).await;
    let base_url = server.url();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = shutdown_rx.await;
        drop(server);
    });
    (base_url, state, shutdown_tx)
}

#[derive(Clone)]
struct OverrideGetState {
    status: StatusCode,
    body: String,
    get_calls: Arc<Mutex<Vec<String>>>,
}

async fn handle_override_get(
    State(state): State<OverrideGetState>,
    Path(provider_key): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !auth.starts_with("Bearer ") {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    state
        .get_calls
        .lock()
        .expect("get_calls lock")
        .push(provider_key);
    (state.status, state.body.clone()).into_response()
}

/// Starts a mock OAuth token API whose GET handler always returns a fixed status/body.
pub async fn start_override_get_oauth_api(
    status: StatusCode,
    body: impl Into<String>,
) -> (String, Arc<Mutex<Vec<String>>>, oneshot::Sender<()>) {
    let get_calls = Arc::new(Mutex::new(Vec::new()));
    let state = OverrideGetState {
        status,
        body: body.into(),
        get_calls: Arc::clone(&get_calls),
    };

    let app = Router::new()
        .route("/v1/oauth-tokens/:provider_key", get(handle_override_get))
        .with_state(state);
    let server = SpawnedServer::bind(app).await;
    let base_url = server.url();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = shutdown_rx.await;
        drop(server);
    });
    (base_url, get_calls, shutdown_tx)
}
