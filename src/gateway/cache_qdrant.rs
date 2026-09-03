// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

#![cfg_attr(not(feature = "distributed"), allow(dead_code, unused_imports))]

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use reqwest::{Client, Method, RequestBuilder};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::error::CliError;

use super::cache::StoredCachedResponse;

const DEFAULT_QDRANT_COLLECTION: &str = "verdictan_llm_cache";
const DEFAULT_QDRANT_TIMEOUT_SECS: u64 = 10;
const MAX_PENDING_ENTRIES: usize = 10_000;
const SEARCH_LIMIT: usize = 5;

#[derive(Clone, Debug)]
pub struct QdrantCacheConfig {
    pub url: String,
    pub collection: String,
    pub api_key: Option<String>,
    pub request_timeout: Duration,
}

impl QdrantCacheConfig {
    pub fn default_collection() -> String {
        DEFAULT_QDRANT_COLLECTION.to_string()
    }

    pub fn default_timeout() -> Duration {
        Duration::from_secs(DEFAULT_QDRANT_TIMEOUT_SECS)
    }
}

#[derive(Clone)]
pub struct QdrantSemanticCacheBackend {
    client: Client,
    config: QdrantCacheConfig,
    pending_exact: Arc<RwLock<HashMap<String, StoredCachedResponse>>>,
}

impl QdrantSemanticCacheBackend {
    pub async fn new(config: QdrantCacheConfig) -> Result<Self, CliError> {
        #[cfg(not(feature = "distributed"))]
        {
            let _ = config;
            Err(CliError::user(
                "VERDICTAN_LLM_CACHE_BACKEND=qdrant requires a CLI build with --features distributed",
            ))
        }

        #[cfg(feature = "distributed")]
        {
            let client = Client::builder()
                .timeout(config.request_timeout)
                .build()
                .map_err(|error| {
                    CliError::internal(format!("failed to build Qdrant client: {error}"))
                })?;
            let backend = Self {
                client,
                config,
                pending_exact: Arc::new(RwLock::new(HashMap::new())),
            };
            backend.validate_connectivity().await?;
            Ok(backend)
        }
    }

    pub async fn get(&self, key: &str) -> Option<StoredCachedResponse> {
        if let Ok(pending) = self.pending_exact.read() {
            if let Some(entry) = pending.get(key) {
                return Some(entry.clone());
            }
        }

        let point_id = point_id_for_key(key);
        let (status, body) = self
            .send_json(Method::GET, self.collection_point_url(&point_id), None)
            .await
            .ok()?;
        if status == reqwest::StatusCode::NOT_FOUND {
            return None;
        }
        let payload = body.get("result")?.get("payload")?;
        serde_json::from_value(payload.get("cached_response")?.clone()).ok()
    }

    pub async fn put(&self, key: &str, entry: StoredCachedResponse, ttl: &Duration) {
        if let Ok(mut pending) = self.pending_exact.write() {
            retain_pending_entries(&mut pending, ttl);
            pending.insert(key.to_string(), entry);
        }
    }

    pub async fn clear(&self) {
        if let Ok(mut pending) = self.pending_exact.write() {
            pending.clear();
        }

        let _ = self
            .send_status(Method::DELETE, self.collection_url(), None)
            .await
            .map_err(|error| {
                tracing::warn!(error = %error, "qdrant cache clear failed");
            });
    }

    pub async fn remove(&self, key: &str) -> bool {
        let mut removed = false;
        if let Ok(mut pending) = self.pending_exact.write() {
            removed = pending.remove(key).is_some();
        }

        let body = json!({
            "points": [point_id_for_key(key)]
        });
        let delete_url = format!("{}/points/delete?wait=true", self.collection_url());
        match self.send_status(Method::POST, delete_url, Some(body)).await {
            Ok(status) if status.is_success() => true,
            Ok(status) if status == reqwest::StatusCode::NOT_FOUND => removed,
            Ok(status) => {
                tracing::warn!(status = %status, cache_key = %key, "qdrant cache remove failed");
                removed
            }
            Err(error) => {
                tracing::warn!(error = %error, cache_key = %key, "qdrant cache remove failed");
                removed
            }
        }
    }

    pub async fn pressure_json(&self) -> serde_json::Value {
        match self
            .send_json(Method::GET, self.collection_url(), None)
            .await
        {
            Ok((_, body)) => serde_json::json!({
                "level": "nominal",
                "estimated_entry_count": body
                    .get("result")
                    .and_then(|result| result.get("points_count"))
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            }),
            Err(error) => {
                tracing::warn!(error = %error, "qdrant cache pressure lookup failed");
                serde_json::json!({
                    "level": "degraded",
                    "estimated_entry_count": serde_json::Value::Null,
                })
            }
        }
    }

    pub async fn store_semantic_embedding(&self, key: &str, embedding: &[f64], _ttl: &Duration) {
        let Some(entry) = self.take_pending_or_existing_entry(key).await else {
            return;
        };

        if let Err(error) = self.ensure_collection(embedding.len()).await {
            tracing::warn!(error = %error, cache_key = %key, "qdrant cache collection ensure failed");
            if let Ok(mut pending) = self.pending_exact.write() {
                pending.insert(key.to_string(), entry);
            }
            return;
        }

        let payload = json!({
            "cache_key": key,
            "cached_response": entry,
        });
        let body = json!({
            "points": [{
                "id": point_id_for_key(key),
                "vector": embedding,
                "payload": payload,
            }]
        });

        let points_url = format!("{}/points?wait=true", self.collection_url());
        if let Err(error) = self.send_status(Method::PUT, points_url, Some(body)).await {
            tracing::warn!(error = %error, cache_key = %key, "qdrant semantic cache put failed");
        }
    }

    pub async fn semantic_lookup_key(
        &self,
        query_embedding: &[f64],
        threshold: f64,
    ) -> Option<String> {
        if query_embedding.is_empty() {
            return None;
        }

        let body = json!({
            "vector": query_embedding,
            "limit": SEARCH_LIMIT,
            "score_threshold": threshold,
            "with_payload": true,
        });
        let search_url = format!("{}/points/search", self.collection_url());
        let (status, body) = self
            .send_json(Method::POST, search_url, Some(body))
            .await
            .ok()?;
        if !status.is_success() {
            return None;
        }
        let results = body.get("result")?.as_array()?;
        for result in results {
            let score = result
                .get("score")
                .and_then(|value| value.as_f64())
                .unwrap_or(0.0);
            if score < threshold {
                continue;
            }
            let payload = result.get("payload")?;
            let _entry: StoredCachedResponse =
                serde_json::from_value(payload.get("cached_response")?.clone()).ok()?;
            if let Some(key) = payload.get("cache_key").and_then(|value| value.as_str()) {
                return Some(key.to_string());
            }
        }

        None
    }

    async fn validate_connectivity(&self) -> Result<(), CliError> {
        let status = self
            .send_status(Method::GET, self.collection_url(), None)
            .await
            .map_err(|error| {
                CliError::network(format!(
                    "failed to connect to Qdrant for VERDICTAN_LLM_CACHE_BACKEND=qdrant: {error}"
                ))
            })?;

        if status.is_success() || status == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(CliError::network(format!(
                "unexpected Qdrant status for VERDICTAN_LLM_CACHE_BACKEND=qdrant: {}",
                status
            )))
        }
    }

    async fn ensure_collection(&self, vector_size: usize) -> Result<(), CliError> {
        let status = self
            .send_status(Method::GET, self.collection_url(), None)
            .await
            .map_err(|error| {
                CliError::network(format!("failed to inspect Qdrant collection: {error}"))
            })?;

        if status.is_success() {
            return Ok(());
        }

        if status != reqwest::StatusCode::NOT_FOUND {
            return Err(CliError::network(format!(
                "unexpected Qdrant collection inspection status: {}",
                status
            )));
        }

        let body = json!({
            "vectors": {
                "size": vector_size,
                "distance": "Cosine"
            }
        });
        let create_status = self
            .send_status(Method::PUT, self.collection_url(), Some(body))
            .await
            .map_err(|error| {
                CliError::network(format!("failed to create Qdrant collection: {error}"))
            })?;
        if create_status.is_success() {
            Ok(())
        } else {
            Err(CliError::network(format!(
                "failed to create Qdrant collection: {}",
                create_status
            )))
        }
    }

    async fn take_pending_or_existing_entry(&self, key: &str) -> Option<StoredCachedResponse> {
        if let Ok(mut pending) = self.pending_exact.write() {
            if let Some(entry) = pending.remove(key) {
                return Some(entry);
            }
        }
        self.get(key).await
    }

    fn request(&self, builder: RequestBuilder) -> RequestBuilder {
        if let Some(api_key) = self.config.api_key.as_deref() {
            builder.header("api-key", api_key)
        } else {
            builder
        }
    }

    async fn send_status(
        &self,
        method: Method,
        url: String,
        body: Option<serde_json::Value>,
    ) -> Result<reqwest::StatusCode, reqwest::Error> {
        let mut request = self.request(self.client.request(method, url));
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await?;
        Ok(response.status())
    }

    async fn send_json(
        &self,
        method: Method,
        url: String,
        body: Option<serde_json::Value>,
    ) -> Result<(reqwest::StatusCode, serde_json::Value), reqwest::Error> {
        let mut request = self.request(self.client.request(method, url));
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await?;
        let status = response.status();
        let body = response.json::<serde_json::Value>().await?;
        Ok((status, body))
    }

    fn collection_url(&self) -> String {
        format!(
            "{}/collections/{}",
            self.config.url.trim_end_matches('/'),
            self.config.collection
        )
    }

    fn collection_point_url(&self, point_id: &str) -> String {
        format!("{}/points/{}", self.collection_url(), point_id)
    }
}

fn point_id_for_key(key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Uuid::from_bytes(bytes).to_string()
}

fn retain_pending_entries(entries: &mut HashMap<String, StoredCachedResponse>, ttl: &Duration) {
    let now = current_unix_secs();
    entries.retain(|_, entry| now.saturating_sub(entry.stored_at_unix_secs()) <= ttl.as_secs());

    if entries.len() < MAX_PENDING_ENTRIES {
        return;
    }

    let mut ordered = entries
        .iter()
        .map(|(key, entry)| (key.clone(), entry.stored_at_unix_secs()))
        .collect::<Vec<_>>();
    ordered.sort_by_key(|(_, stored_at)| *stored_at);
    let remove_count = entries.len() - MAX_PENDING_ENTRIES + 1;
    for (key, _) in ordered.into_iter().take(remove_count) {
        entries.remove(&key);
    }
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(all(test, feature = "distributed"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::{
        current_unix_secs, point_id_for_key, retain_pending_entries, QdrantCacheConfig,
        QdrantSemanticCacheBackend, MAX_PENDING_ENTRIES, SEARCH_LIMIT,
    };
    use crate::gateway::cache::StoredCachedResponse;
    use axum::{
        extract::{Path, State},
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::{get, post, put},
        Json, Router,
    };
    use base64::Engine;
    use serde_json::json;
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex, RwLock},
        thread::JoinHandle,
        time::Duration,
    };

    fn block_on<T>(fut: impl std::future::Future<Output = T>) -> T {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => tokio::task::block_in_place(|| handle.block_on(fut)),
            Err(_) => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime")
                .block_on(fut),
        }
    }

    #[derive(Clone)]
    struct MockPoint {
        vector: Vec<f64>,
        payload: serde_json::Value,
    }

    #[derive(Clone, Default)]
    struct MockCollection {
        points: HashMap<String, MockPoint>,
    }

    type Collections = Arc<Mutex<HashMap<String, MockCollection>>>;

    #[derive(Clone, Default)]
    struct MockQdrantState {
        collections: Collections,
        behavior: Arc<Mutex<MockQdrantBehavior>>,
    }

    #[derive(Clone, Debug, Default)]
    struct MockQdrantBehavior {
        collection_get_status: Option<StatusCode>,
        collection_put_status: Option<StatusCode>,
        delete_collection_status: Option<StatusCode>,
        upsert_points_status: Option<StatusCode>,
        delete_points_status: Option<StatusCode>,
        search_override: Option<(StatusCode, serde_json::Value)>,
        search_call_count: usize,
        last_collection_put_body: Option<serde_json::Value>,
        last_upsert_body: Option<serde_json::Value>,
        last_upsert_api_key: Option<String>,
        last_search_body: Option<serde_json::Value>,
        last_search_api_key: Option<String>,
        last_delete_points_body: Option<serde_json::Value>,
        last_delete_points_api_key: Option<String>,
    }

    struct MockQdrantServer {
        url: String,
        state: MockQdrantState,
        _handle: JoinHandle<()>,
    }

    impl MockQdrantState {
        fn api_key(headers: &HeaderMap) -> Option<String> {
            headers
                .get("api-key")
                .and_then(|value| value.to_str().ok())
                .map(ToString::to_string)
        }

        fn set_collection_get_status(&self, status: StatusCode) {
            self.behavior
                .lock()
                .expect("mock behavior lock")
                .collection_get_status = Some(status);
        }

        fn set_collection_put_status(&self, status: StatusCode) {
            self.behavior
                .lock()
                .expect("mock behavior lock")
                .collection_put_status = Some(status);
        }

        fn set_delete_points_status(&self, status: StatusCode) {
            self.behavior
                .lock()
                .expect("mock behavior lock")
                .delete_points_status = Some(status);
        }

        fn set_search_override(&self, status: StatusCode, body: serde_json::Value) {
            self.behavior
                .lock()
                .expect("mock behavior lock")
                .search_override = Some((status, body));
        }

        fn insert_point(
            &self,
            collection: &str,
            point_id: &str,
            vector: Vec<f64>,
            payload: serde_json::Value,
        ) {
            self.collections
                .lock()
                .expect("collections lock")
                .entry(collection.to_string())
                .or_default()
                .points
                .insert(point_id.to_string(), MockPoint { vector, payload });
        }

        fn collection_point_count(&self, collection: &str) -> usize {
            self.collections
                .lock()
                .expect("collections lock")
                .get(collection)
                .map(|collection| collection.points.len())
                .unwrap_or(0)
        }

        fn search_call_count(&self) -> usize {
            self.behavior
                .lock()
                .expect("mock behavior lock")
                .search_call_count
        }

        fn last_collection_put_body(&self) -> Option<serde_json::Value> {
            self.behavior
                .lock()
                .expect("mock behavior lock")
                .last_collection_put_body
                .clone()
        }

        fn last_upsert_body(&self) -> Option<serde_json::Value> {
            self.behavior
                .lock()
                .expect("mock behavior lock")
                .last_upsert_body
                .clone()
        }

        fn last_upsert_api_key(&self) -> Option<String> {
            self.behavior
                .lock()
                .expect("mock behavior lock")
                .last_upsert_api_key
                .clone()
        }

        fn last_search_body(&self) -> Option<serde_json::Value> {
            self.behavior
                .lock()
                .expect("mock behavior lock")
                .last_search_body
                .clone()
        }

        fn last_search_api_key(&self) -> Option<String> {
            self.behavior
                .lock()
                .expect("mock behavior lock")
                .last_search_api_key
                .clone()
        }

        fn last_delete_points_body(&self) -> Option<serde_json::Value> {
            self.behavior
                .lock()
                .expect("mock behavior lock")
                .last_delete_points_body
                .clone()
        }

        fn last_delete_points_api_key(&self) -> Option<String> {
            self.behavior
                .lock()
                .expect("mock behavior lock")
                .last_delete_points_api_key
                .clone()
        }
    }

    impl MockQdrantServer {
        fn start() -> Self {
            let state = MockQdrantState {
                collections: Arc::new(Mutex::new(HashMap::new())),
                behavior: Arc::new(Mutex::new(MockQdrantBehavior::default())),
            };
            let (tx, rx) = std::sync::mpsc::channel();
            let server_state = state.clone();
            let handle = std::thread::spawn(move || {
                let runtime = tokio::runtime::Runtime::new().expect("mock qdrant runtime");
                runtime.block_on(async move {
                    let app = Router::new()
                        .route(
                            "/collections/:collection",
                            get(get_collection)
                                .put(put_collection)
                                .delete(delete_collection),
                        )
                        .route("/collections/:collection/points", put(upsert_points))
                        .route(
                            "/collections/:collection/points/delete",
                            post(delete_points),
                        )
                        .route(
                            "/collections/:collection/points/search",
                            post(search_points),
                        )
                        .route("/collections/:collection/points/:point_id", get(get_point))
                        .with_state(server_state);
                    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                        .await
                        .expect("bind mock qdrant");
                    let addr = listener.local_addr().expect("mock qdrant addr");
                    tx.send(format!("http://{addr}")).expect("send qdrant url");
                    axum::serve(listener, app).await.expect("serve mock qdrant");
                });
            });

            Self {
                url: rx.recv().expect("receive qdrant url"),
                state,
                _handle: handle,
            }
        }

        async fn backend(&self, api_key: Option<&str>) -> QdrantSemanticCacheBackend {
            QdrantSemanticCacheBackend::new(QdrantCacheConfig {
                url: self.url.clone(),
                collection: "test-cache".to_string(),
                api_key: api_key.map(ToString::to_string),
                request_timeout: Duration::from_secs(2),
            })
            .await
            .expect("qdrant backend")
        }
    }

    async fn get_collection(
        State(state): State<MockQdrantState>,
        Path(collection): Path<String>,
    ) -> impl axum::response::IntoResponse {
        if let Some(status) = state
            .behavior
            .lock()
            .expect("mock behavior lock")
            .collection_get_status
        {
            if status.is_success() {
                let points_count = state.collection_point_count(&collection);
                return (
                    status,
                    Json(json!({
                        "status": "ok",
                        "result": { "points_count": points_count }
                    })),
                )
                    .into_response();
            }
            return status.into_response();
        }

        let collections = state.collections.lock().expect("collections lock");
        if let Some(collection_state) = collections.get(&collection) {
            (
                StatusCode::OK,
                Json(json!({
                    "status": "ok",
                    "result": { "points_count": collection_state.points.len() }
                })),
            )
                .into_response()
        } else {
            StatusCode::NOT_FOUND.into_response()
        }
    }

    async fn put_collection(
        State(state): State<MockQdrantState>,
        Path(collection): Path<String>,
        Json(payload): Json<serde_json::Value>,
    ) -> impl axum::response::IntoResponse {
        {
            let mut behavior = state.behavior.lock().expect("mock behavior lock");
            behavior.last_collection_put_body = Some(payload);
            if let Some(status) = behavior.collection_put_status {
                return status.into_response();
            }
        }

        state
            .collections
            .lock()
            .expect("collections lock")
            .entry(collection)
            .or_default();
        (StatusCode::OK, Json(json!({"status":"ok","result":true}))).into_response()
    }

    async fn delete_collection(
        State(state): State<MockQdrantState>,
        Path(collection): Path<String>,
    ) -> impl axum::response::IntoResponse {
        if let Some(status) = state
            .behavior
            .lock()
            .expect("mock behavior lock")
            .delete_collection_status
        {
            return status.into_response();
        }

        let removed = state
            .collections
            .lock()
            .expect("collections lock")
            .remove(&collection)
            .is_some();
        if removed {
            (StatusCode::OK, Json(json!({"status":"ok","result":true}))).into_response()
        } else {
            StatusCode::NOT_FOUND.into_response()
        }
    }

    async fn upsert_points(
        State(state): State<MockQdrantState>,
        Path(collection): Path<String>,
        headers: HeaderMap,
        Json(payload): Json<serde_json::Value>,
    ) -> impl axum::response::IntoResponse {
        {
            let mut behavior = state.behavior.lock().expect("mock behavior lock");
            behavior.last_upsert_api_key = MockQdrantState::api_key(&headers);
            behavior.last_upsert_body = Some(payload.clone());
            if let Some(status) = behavior.upsert_points_status {
                return status.into_response();
            }
        }

        let mut collections = state.collections.lock().expect("collections lock");
        let collection_state = collections.entry(collection).or_default();
        for point in payload
            .get("points")
            .and_then(|points| points.as_array())
            .cloned()
            .unwrap_or_default()
        {
            let id = point
                .get("id")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string();
            let vector = point
                .get("vector")
                .and_then(|value| value.as_array())
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.as_f64())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let payload = point.get("payload").cloned().unwrap_or_else(|| json!({}));
            collection_state
                .points
                .insert(id, MockPoint { vector, payload });
        }
        (StatusCode::OK, Json(json!({"status":"ok","result":true}))).into_response()
    }

    async fn delete_points(
        State(state): State<MockQdrantState>,
        Path(collection): Path<String>,
        headers: HeaderMap,
        Json(payload): Json<serde_json::Value>,
    ) -> impl axum::response::IntoResponse {
        {
            let mut behavior = state.behavior.lock().expect("mock behavior lock");
            behavior.last_delete_points_api_key = MockQdrantState::api_key(&headers);
            behavior.last_delete_points_body = Some(payload.clone());
            if let Some(status) = behavior.delete_points_status {
                return status.into_response();
            }
        }

        let mut collections = state.collections.lock().expect("collections lock");
        let Some(collection_state) = collections.get_mut(&collection) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let ids = payload
            .get("points")
            .and_then(|value| value.as_array())
            .cloned()
            .unwrap_or_default();
        for point_id in ids {
            if let Some(point_id) = point_id.as_str() {
                collection_state.points.remove(point_id);
            }
        }

        (StatusCode::OK, Json(json!({"status":"ok","result":true}))).into_response()
    }

    async fn get_point(
        State(state): State<MockQdrantState>,
        Path((collection, point_id)): Path<(String, String)>,
    ) -> impl axum::response::IntoResponse {
        let collections = state.collections.lock().expect("collections lock");
        let Some(collection_state) = collections.get(&collection) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let Some(point) = collection_state.points.get(&point_id) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "result": { "id": point_id, "payload": point.payload }
            })),
        )
            .into_response()
    }

    async fn search_points(
        State(state): State<MockQdrantState>,
        Path(collection): Path<String>,
        headers: HeaderMap,
        Json(payload): Json<serde_json::Value>,
    ) -> impl axum::response::IntoResponse {
        {
            let mut behavior = state.behavior.lock().expect("mock behavior lock");
            behavior.search_call_count += 1;
            behavior.last_search_api_key = MockQdrantState::api_key(&headers);
            behavior.last_search_body = Some(payload.clone());
            if let Some((status, body)) = behavior.search_override.clone() {
                return (status, Json(body)).into_response();
            }
        }

        let query = payload
            .get("vector")
            .and_then(|value| value.as_array())
            .map(|values| {
                values
                    .iter()
                    .filter_map(|value| value.as_f64())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let threshold = payload
            .get("score_threshold")
            .and_then(|value| value.as_f64())
            .unwrap_or(0.0);
        let collections = state.collections.lock().expect("collections lock");
        let Some(collection_state) = collections.get(&collection) else {
            return (StatusCode::OK, Json(json!({"status":"ok","result":[]}))).into_response();
        };

        let mut results = collection_state
            .points
            .iter()
            .map(|(id, point)| {
                let score = cosine(&query, &point.vector);
                json!({"id": id, "score": score, "payload": point.payload})
            })
            .filter(|item| {
                item.get("score")
                    .and_then(|value| value.as_f64())
                    .unwrap_or(0.0)
                    >= threshold
            })
            .collect::<Vec<_>>();
        results.sort_by(|left, right| {
            right["score"]
                .as_f64()
                .partial_cmp(&left["score"].as_f64())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        (
            StatusCode::OK,
            Json(json!({"status":"ok","result":results})),
        )
            .into_response()
    }

    fn cosine(a: &[f64], b: &[f64]) -> f64 {
        if a.len() != b.len() || a.is_empty() {
            return 0.0;
        }
        let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let mag_a: f64 = a.iter().map(|value| value * value).sum::<f64>().sqrt();
        let mag_b: f64 = b.iter().map(|value| value * value).sum::<f64>().sqrt();
        if mag_a == 0.0 || mag_b == 0.0 {
            return 0.0;
        }
        (dot / (mag_a * mag_b)).clamp(-1.0, 1.0)
    }

    fn stored_response(body: &str) -> StoredCachedResponse {
        serde_json::from_value(json!({
            "stored_at_unix_secs": 1,
            "status": 200,
            "headers": [],
            "body_base64": base64::engine::general_purpose::STANDARD.encode(body.as_bytes()),
        }))
        .expect("stored cached response")
    }

    fn stored_response_at(body: &str, stored_at_unix_secs: u64) -> StoredCachedResponse {
        serde_json::from_value(json!({
            "stored_at_unix_secs": stored_at_unix_secs,
            "status": 200,
            "headers": [],
            "body_base64": base64::engine::general_purpose::STANDARD.encode(body.as_bytes()),
        }))
        .expect("stored cached response")
    }

    fn offline_backend(api_key: Option<&str>) -> QdrantSemanticCacheBackend {
        QdrantSemanticCacheBackend {
            client: reqwest::Client::builder()
                .timeout(Duration::from_millis(50))
                .build()
                .expect("offline qdrant client"),
            config: QdrantCacheConfig {
                url: "http://127.0.0.1:9/".to_string(),
                collection: "test-cache".to_string(),
                api_key: api_key.map(ToString::to_string),
                request_timeout: Duration::from_millis(50),
            },
            pending_exact: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    #[test]
    fn helper_defaults_are_stable() {
        assert_eq!(
            QdrantCacheConfig::default_collection(),
            "verdictan_llm_cache".to_string()
        );
        assert_eq!(
            QdrantCacheConfig::default_timeout(),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn point_ids_are_deterministic_for_cache_keys() {
        let first = point_id_for_key("cache-key");
        let second = point_id_for_key("cache-key");
        let third = point_id_for_key("other-key");

        assert_eq!(first, second);
        assert_ne!(first, third);
        assert!(uuid::Uuid::parse_str(&first).is_ok());
    }

    #[test]
    fn request_adds_api_key_header_when_configured() {
        let backend = offline_backend(Some("secret-key"));
        let request = backend
            .request(backend.client.get(backend.collection_url()))
            .build()
            .expect("qdrant request");

        assert_eq!(request.headers()["api-key"], "secret-key");
    }

    #[test]
    fn collection_urls_trim_trailing_slashes() {
        let backend = offline_backend(None);
        assert_eq!(
            backend.collection_url(),
            "http://127.0.0.1:9/collections/test-cache"
        );
        assert_eq!(
            backend.collection_point_url("point-1"),
            "http://127.0.0.1:9/collections/test-cache/points/point-1"
        );
    }

    #[test]
    fn point_id_for_key_is_stable_and_uuid_shaped() {
        let first = point_id_for_key("cache-key");
        let second = point_id_for_key("cache-key");
        let other = point_id_for_key("other-cache-key");

        assert_eq!(first, second);
        assert_ne!(first, other);
        assert!(uuid::Uuid::parse_str(&first).is_ok());
    }

    #[test]
    fn pending_entries_are_pruned_and_capped() {
        let now = current_unix_secs();
        let mut entries = HashMap::new();
        entries.insert(
            "expired".to_string(),
            stored_response_at("expired", now.saturating_sub(10)),
        );
        for idx in 0..=MAX_PENDING_ENTRIES {
            entries.insert(
                format!("fresh-{idx}"),
                stored_response_at("fresh", now.saturating_sub((idx % 2) as u64)),
            );
        }

        retain_pending_entries(&mut entries, &Duration::from_secs(5));

        assert!(!entries.contains_key("expired"));
        assert!(entries.len() < MAX_PENDING_ENTRIES);
    }

    #[test]
    fn retain_pending_entries_evicts_oldest_entry_when_at_capacity() {
        let now = current_unix_secs();
        let mut entries = HashMap::new();
        for index in 0..MAX_PENDING_ENTRIES {
            let stored_at = if index == 0 {
                now.saturating_sub(1_000)
            } else {
                now
            };
            entries.insert(
                format!("key-{index}"),
                stored_response_at("body", stored_at),
            );
        }

        retain_pending_entries(&mut entries, &Duration::from_secs(60));

        assert_eq!(entries.len(), MAX_PENDING_ENTRIES - 1);
        assert!(!entries.contains_key("key-0"));
    }

    #[test]
    fn take_pending_or_existing_entry_prefers_pending_cache() {
        let backend = offline_backend(None);
        block_on(backend.put(
            "pending-key",
            stored_response("pending-body"),
            &Duration::from_secs(60),
        ));

        let entry =
            block_on(backend.take_pending_or_existing_entry("pending-key")).expect("pending entry");

        assert_eq!(entry.stored_at_unix_secs(), 1);
        assert!(backend
            .pending_exact
            .read()
            .expect("pending lock")
            .get("pending-key")
            .is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn take_pending_or_existing_entry_falls_back_to_remote_exact_cache() {
        let server = MockQdrantServer::start();
        server.state.insert_point(
            "test-cache",
            &point_id_for_key("remote-key"),
            vec![1.0],
            json!({
                "cache_key": "remote-key",
                "cached_response": serde_json::to_value(stored_response("remote-body")).expect("response json"),
            }),
        );
        let backend = block_on(server.backend(None));

        let entry = block_on(backend.take_pending_or_existing_entry("remote-key"))
            .expect("remote cached entry");

        assert_eq!(entry.stored_at_unix_secs(), 1);
        assert!(backend
            .pending_exact
            .read()
            .expect("pending lock")
            .get("remote-key")
            .is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn new_maps_unexpected_connectivity_status_to_network_error() {
        let server = MockQdrantServer::start();
        server
            .state
            .set_collection_get_status(StatusCode::SERVICE_UNAVAILABLE);

        let result = block_on(QdrantSemanticCacheBackend::new(QdrantCacheConfig {
            url: server.url.clone(),
            collection: "test-cache".to_string(),
            api_key: None,
            request_timeout: Duration::from_secs(2),
        }));
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("connectivity error expected"),
        };

        assert_eq!(error.error_code(), "cli.network_error");
        let message = error.to_string();
        assert!(message.contains("unexpected Qdrant status"));
        assert!(message.contains("503"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_returns_none_for_missing_or_malformed_remote_payloads() {
        let server = MockQdrantServer::start();
        server.state.insert_point(
            "test-cache",
            &point_id_for_key("malformed-key"),
            vec![1.0],
            json!({
                "cached_response": { "status": "bad" }
            }),
        );
        let backend = block_on(server.backend(None));

        assert!(block_on(backend.get("missing-key")).is_none());
        assert!(block_on(backend.get("malformed-key")).is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn store_semantic_embedding_requeues_entry_when_collection_create_fails() {
        let server = MockQdrantServer::start();
        server
            .state
            .set_collection_put_status(StatusCode::INTERNAL_SERVER_ERROR);
        let backend = block_on(server.backend(None));
        let entry = stored_response("qdrant-body");

        block_on(backend.put("cache-key", entry.clone(), &Duration::from_secs(60)));
        block_on(backend.store_semantic_embedding(
            "cache-key",
            &[1.0, 0.0, 0.0],
            &Duration::from_secs(60),
        ));

        assert_eq!(
            backend
                .pending_exact
                .read()
                .expect("pending lock")
                .get("cache-key")
                .cloned()
                .expect("requeued entry")
                .stored_at_unix_secs(),
            entry.stored_at_unix_secs()
        );
        assert_eq!(
            server.state.last_collection_put_body(),
            Some(json!({
                "vectors": {
                    "size": 3,
                    "distance": "Cosine"
                }
            }))
        );
        assert_eq!(server.state.collection_point_count("test-cache"), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn store_semantic_embedding_sends_expected_upsert_payload_and_api_key() {
        let server = MockQdrantServer::start();
        let backend = block_on(server.backend(Some("secret-key")));
        let entry = stored_response("qdrant-body");

        block_on(backend.put("cache-key", entry.clone(), &Duration::from_secs(60)));
        block_on(backend.store_semantic_embedding(
            "cache-key",
            &[1.0, 2.0, 3.0],
            &Duration::from_secs(60),
        ));

        assert_eq!(
            server.state.last_upsert_api_key().as_deref(),
            Some("secret-key")
        );
        assert_eq!(
            server.state.last_upsert_body(),
            Some(json!({
                "points": [{
                    "id": point_id_for_key("cache-key"),
                    "vector": [1.0, 2.0, 3.0],
                    "payload": {
                        "cache_key": "cache-key",
                        "cached_response": serde_json::to_value(entry).expect("entry json"),
                    },
                }]
            }))
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn semantic_lookup_key_skips_low_scores_and_preserves_search_request_shape() {
        let server = MockQdrantServer::start();
        let backend = block_on(server.backend(Some("search-key")));

        server.state.set_search_override(
            StatusCode::OK,
            json!({
                "status": "ok",
                "result": [
                    {
                        "score": 0.40,
                        "payload": {
                            "cache_key": "too-low",
                            "cached_response": serde_json::to_value(stored_response("low")).expect("low response json"),
                        }
                    },
                    {
                        "score": 0.91,
                        "payload": {
                            "cache_key": "semantic-hit",
                            "cached_response": serde_json::to_value(stored_response("hit")).expect("hit response json"),
                        }
                    }
                ]
            }),
        );

        let result =
            block_on(backend.semantic_lookup_key(&[0.25, 0.75], 0.85)).expect("semantic key");

        assert_eq!(result, "semantic-hit");
        assert_eq!(
            server.state.last_search_api_key().as_deref(),
            Some("search-key")
        );
        assert_eq!(
            server.state.last_search_body(),
            Some(json!({
                "vector": [0.25, 0.75],
                "limit": SEARCH_LIMIT,
                "score_threshold": 0.85,
                "with_payload": true,
            }))
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn semantic_lookup_key_returns_none_for_empty_or_invalid_results() {
        let server = MockQdrantServer::start();
        let backend = block_on(server.backend(None));

        assert!(block_on(backend.semantic_lookup_key(&[], 0.5)).is_none());
        assert_eq!(server.state.search_call_count(), 0);

        server.state.set_search_override(
            StatusCode::OK,
            json!({
                "status": "ok",
                "result": [{
                    "score": 0.95,
                    "payload": {
                        "cache_key": "broken",
                        "cached_response": { "status": "bad" }
                    }
                }]
            }),
        );

        assert!(block_on(backend.semantic_lookup_key(&[0.5, 0.5], 0.8)).is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn remove_sends_expected_delete_payload_and_uses_pending_result_on_not_found() {
        let server = MockQdrantServer::start();
        server.state.set_delete_points_status(StatusCode::NOT_FOUND);
        let backend = block_on(server.backend(Some("secret-key")));
        block_on(backend.put(
            "cache-key",
            stored_response("pending-body"),
            &Duration::from_secs(60),
        ));

        assert!(block_on(backend.remove("cache-key")));
        assert!(backend
            .pending_exact
            .read()
            .expect("pending lock")
            .get("cache-key")
            .is_none());
        assert_eq!(
            server.state.last_delete_points_api_key().as_deref(),
            Some("secret-key")
        );
        assert_eq!(
            server.state.last_delete_points_body(),
            Some(json!({
                "points": [point_id_for_key("cache-key")]
            }))
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn remove_returns_pending_result_when_remote_delete_errors() {
        let server = MockQdrantServer::start();
        server
            .state
            .set_delete_points_status(StatusCode::INTERNAL_SERVER_ERROR);
        let backend = block_on(server.backend(None));
        block_on(backend.put(
            "cache-key",
            stored_response("pending-body"),
            &Duration::from_secs(60),
        ));

        assert!(block_on(backend.remove("cache-key")));
        assert!(backend
            .pending_exact
            .read()
            .expect("pending lock")
            .get("cache-key")
            .is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn remove_returns_false_for_remote_not_found_without_pending_entry() {
        let server = MockQdrantServer::start();
        server.state.set_delete_points_status(StatusCode::NOT_FOUND);
        let backend = block_on(server.backend(None));

        assert!(!block_on(backend.remove("missing-key")));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pressure_json_reports_nominal_for_live_collection_counts() {
        let server = MockQdrantServer::start();
        server.state.insert_point(
            "test-cache",
            &point_id_for_key("cache-key"),
            vec![1.0, 0.0],
            json!({
                "cache_key": "cache-key",
                "cached_response": serde_json::to_value(stored_response("body")).expect("response json"),
            }),
        );
        let backend = block_on(server.backend(None));

        assert_eq!(
            block_on(backend.pressure_json()),
            json!({
                "level": "nominal",
                "estimated_entry_count": 1,
            })
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn clear_deletes_remote_collection_when_available() {
        let server = MockQdrantServer::start();
        server.state.insert_point(
            "test-cache",
            &point_id_for_key("cache-key"),
            vec![1.0],
            json!({
                "cache_key": "cache-key",
                "cached_response": serde_json::to_value(stored_response("body")).expect("response json"),
            }),
        );
        let backend = block_on(server.backend(None));
        block_on(backend.put(
            "pending-key",
            stored_response("pending-body"),
            &Duration::from_secs(60),
        ));

        block_on(backend.clear());

        assert!(backend
            .pending_exact
            .read()
            .expect("pending lock")
            .is_empty());
        assert_eq!(server.state.collection_point_count("test-cache"), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn qdrant_backend_round_trips_exact_and_semantic_entries() {
        let server = MockQdrantServer::start();
        let backend = block_on(server.backend(None));

        block_on(backend.put(
            "cache-key",
            stored_response("qdrant-body"),
            &Duration::from_secs(60),
        ));
        block_on(backend.store_semantic_embedding(
            "cache-key",
            &[1.0, 0.0, 0.0],
            &Duration::from_secs(60),
        ));

        let exact = block_on(backend.get("cache-key")).expect("qdrant exact hit");
        let semantic = block_on(backend.semantic_lookup_key(&[0.99, 0.01, 0.0], 0.85))
            .expect("qdrant semantic hit");

        assert_eq!(semantic, "cache-key");
        assert_eq!(exact.stored_at_unix_secs(), 1);
    }

    // ── Additional edge cases ────────────────────────────────────────────

    #[test]
    fn get_from_pending_cache_returns_entry() {
        let backend = offline_backend(None);
        block_on(backend.put(
            "in-pending",
            stored_response("pending value"),
            &Duration::from_secs(60),
        ));
        let entry = block_on(backend.get("in-pending")).expect("should find in pending");
        assert_eq!(entry.stored_at_unix_secs(), 1);
    }

    #[test]
    fn put_respects_max_pending_cap_via_retain() {
        let backend = offline_backend(None);
        for i in 0..100 {
            block_on(backend.put(
                &format!("key-{i}"),
                stored_response("body"),
                &Duration::from_secs(60),
            ));
        }
        let count = backend.pending_exact.read().expect("lock").len();
        assert!(count <= MAX_PENDING_ENTRIES);
    }

    #[test]
    fn remove_from_pending_only_returns_true() {
        let backend = offline_backend(None);
        block_on(backend.put(
            "cache-key",
            stored_response("body"),
            &Duration::from_secs(60),
        ));
        let removed = block_on(backend.remove("cache-key"));
        assert!(removed);
        assert!(backend
            .pending_exact
            .read()
            .expect("lock")
            .get("cache-key")
            .is_none());
    }

    #[test]
    fn remove_nonexistent_key_returns_false() {
        let backend = offline_backend(None);
        let removed = block_on(backend.remove("no-such-key"));
        assert!(!removed);
    }

    #[test]
    fn semantic_lookup_key_empty_embedding_returns_none_without_network() {
        let backend = offline_backend(None);
        assert!(block_on(backend.semantic_lookup_key(&[], 0.5)).is_none());
    }

    #[test]
    fn store_semantic_embedding_no_entry_is_noop() {
        let backend = offline_backend(None);
        block_on(backend.store_semantic_embedding(
            "nonexistent",
            &[1.0, 0.0],
            &Duration::from_secs(60),
        ));
        assert!(backend.pending_exact.read().expect("lock").is_empty());
    }

    #[test]
    fn request_without_api_key_has_no_api_key_header() {
        let backend = offline_backend(None);
        let request = backend
            .request(backend.client.get(backend.collection_url()))
            .build()
            .expect("qdrant request");
        assert!(request.headers().get("api-key").is_none());
    }

    #[test]
    fn retain_pending_entries_does_nothing_when_under_cap() {
        let now = current_unix_secs();
        let mut entries = HashMap::new();
        for i in 0..5 {
            entries.insert(format!("key-{i}"), stored_response_at("body", now));
        }
        retain_pending_entries(&mut entries, &Duration::from_secs(60));
        assert_eq!(entries.len(), 5);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn remove_with_remote_success() {
        let server = MockQdrantServer::start();
        server.state.insert_point(
            "test-cache",
            &point_id_for_key("remote-key"),
            vec![1.0],
            json!({
                "cache_key": "remote-key",
                "cached_response": serde_json::to_value(stored_response("body")).expect("json"),
            }),
        );
        let backend = block_on(server.backend(None));
        let result = block_on(backend.remove("remote-key"));
        assert!(result);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn semantic_lookup_returns_none_on_non_success_status() {
        let server = MockQdrantServer::start();
        server
            .state
            .set_search_override(axum::http::StatusCode::INTERNAL_SERVER_ERROR, json!({}));
        let backend = block_on(server.backend(None));
        assert!(block_on(backend.semantic_lookup_key(&[0.5, 0.5], 0.5)).is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ensure_collection_non_404_non_success_returns_error() {
        let server = MockQdrantServer::start();
        let backend = block_on(server.backend(None));
        server
            .state
            .set_collection_get_status(axum::http::StatusCode::FORBIDDEN);
        block_on(backend.put("k", stored_response("body"), &Duration::from_secs(60)));
        block_on(backend.store_semantic_embedding("k", &[1.0, 0.0], &Duration::from_secs(60)));
        assert!(backend
            .pending_exact
            .read()
            .expect("lock")
            .contains_key("k"));
    }
}
