// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Callback integrations for third-party observability platforms.
//!
//! Each callback sink sends a `CallbackEvent` to a specific platform after
//! every proxied LLM request. The `CallbackRouter` fans out events to all
//! configured sinks concurrently.
//!
//! # Legacy boundary
//!
//! These sinks are **best-effort gateway observability callbacks**, not the
//! API-owned SIEM delivery path. AI Usage SIEM streaming (`splunk`, `elastic`,
//! `datadog`, `generic_https_json`) is implemented in `api/src/siem_adapters.rs`
//! with KMS envelope credentials, SSRF pinning, fencing, and DLQ. Do not treat
//! this module as SIEM connector evidence. Configuring those SIEM destination
//! kinds as callback `type` values is rejected.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::secret_key_ref::parse_env_secret_key_name;

/// Event emitted after each proxied request, delivered to all callback sinks.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CallbackEvent {
    pub request_id: String,
    pub provider: String,
    pub model: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub cost: f64,
    pub latency_ms: u64,
    pub status: u16,
    pub cache_hit: bool,
    pub metadata: HashMap<String, String>,

    // Privacy controls — set from org callback-privacy settings.
    /// When `true`, message/prompt content has been stripped before dispatch.
    #[serde(default)]
    pub message_logging_enabled: bool,
    /// When `true`, user identifiers are redacted.
    #[serde(default)]
    pub user_redacted: bool,

    // Identity and quota fields.
    /// Virtual-key or API-key identifier from the gateway request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Caller user identifier (from API token binding or signed assertion).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Team identifier associated with the key or assertion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    /// Remaining budget for the caller at the time of this request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_remaining: Option<f64>,
    /// Configured budget limit for the caller (0 means unlimited).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_limit: Option<f64>,
    /// How caller identity was established: "header_soft", "api_token", or "signed_assertion".
    #[serde(default = "default_identity_assertion_kind")]
    pub identity_assertion_kind: String,
    /// Grant actions this event matches (used for fidelity enforcement).
    #[serde(default)]
    pub grant_actions: Vec<String>,
    /// Session identifier extracted from x-session-id header or request metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

fn default_identity_assertion_kind() -> String {
    "header_soft".to_string()
}

impl CallbackEvent {
    /// Return a privacy-scrubbed copy of this event based on org settings.
    pub fn scrub_for_privacy(&self, turn_off_message_logging: bool, redact_user: bool) -> Self {
        let mut scrubbed = self.clone();

        if turn_off_message_logging {
            scrubbed.message_logging_enabled = false;
            // Remove any message content from metadata.
            scrubbed.metadata.remove("prompt");
            scrubbed.metadata.remove("completion");
            scrubbed.metadata.remove("messages");
            scrubbed.metadata.remove("input");
            scrubbed.metadata.remove("output");
        } else {
            scrubbed.message_logging_enabled = true;
        }

        if redact_user {
            scrubbed.user_redacted = true;
            scrubbed.metadata.remove("user");
            scrubbed.metadata.remove("user_id");
            scrubbed.metadata.remove("end_user");
            // Redact identity fields when user data is being stripped.
            scrubbed.key_id = None;
            scrubbed.user_id = None;
            scrubbed.team_id = None;
            scrubbed.budget_remaining = None;
            scrubbed.budget_limit = None;
        }

        scrubbed
    }

    /// Strip payload fields to the requested grant fidelity level.
    ///
    /// - `"event_only"`: remove key_id, user_id, team_id, budget_remaining, budget_limit, identity_assertion_kind
    /// - `"identity"`: keep identity fields, remove budget_remaining and budget_limit
    /// - `"full"`: keep everything
    fn apply_payload_fidelity(&mut self, fidelity: &str) {
        match fidelity {
            "full" => {}
            "identity" => {
                self.budget_remaining = None;
                self.budget_limit = None;
            }
            _ => {
                // event_only
                self.key_id = None;
                self.user_id = None;
                self.team_id = None;
                self.budget_remaining = None;
                self.budget_limit = None;
                self.identity_assertion_kind = default_identity_assertion_kind();
            }
        }
    }
}

/// Trait implemented by each callback integration.
pub trait CallbackSink: Send + Sync {
    /// Deliver an event to the external platform. Implementations should be
    /// best-effort; failures are logged, not propagated.
    fn send<'a>(
        &'a self,
        event: &'a CallbackEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

    /// Human-readable name, used in tracing spans and configuration parsing.
    fn name(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// Langfuse
// ---------------------------------------------------------------------------

/// Sends events to the Langfuse ingestion API (`/api/public/ingestion`).
#[derive(Debug, Clone)]
pub struct LangfuseCallback {
    pub host: String,
    pub public_key: String,
    pub secret_key: String,
}

impl CallbackSink for LangfuseCallback {
    fn send<'a>(
        &'a self,
        event: &'a CallbackEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let url = format!("{}/api/public/ingestion", self.host.trim_end_matches('/'));
            let body = serde_json::json!({
                "batch": [{
                    "type": "generation-create",
                    "body": {
                        "traceId": &event.request_id,
                        "model": &event.model,
                        "usage": {
                            "promptTokens": event.prompt_tokens,
                            "completionTokens": event.completion_tokens,
                            "totalCost": event.cost,
                        },
                        "latency": event.latency_ms,
                        "statusMessage": event.status.to_string(),
                        "metadata": &event.metadata,
                    }
                }]
            });

            let client = super::http_client::shared_gateway_http_client()
                .map_err(|error| format!("gateway HTTP client: {error}"))?;
            let resp = client
                .post(&url)
                .basic_auth(&self.public_key, Some(&self.secret_key))
                .json(&body)
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await
                .map_err(|e| format!("langfuse send error: {e}"))?;

            if !resp.status().is_success() {
                return Err(format!("langfuse HTTP {}", resp.status()));
            }
            Ok(())
        })
    }

    fn name(&self) -> &'static str {
        "langfuse"
    }
}

// ---------------------------------------------------------------------------
// Datadog
// ---------------------------------------------------------------------------

/// Sends events to the Datadog Log Intake API.
#[derive(Debug, Clone)]
pub struct DatadogCallback {
    pub api_key: String,
    pub site: String,
    pub service_name: String,
    pub tags: Vec<String>,
}

impl CallbackSink for DatadogCallback {
    fn send<'a>(
        &'a self,
        event: &'a CallbackEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let url = format!("https://http-intake.logs.{}/api/v2/logs", self.site);
            let tags_str = self.tags.join(",");
            let body = serde_json::json!([{
                "ddsource": "verdictan",
                "ddtags": tags_str,
                "hostname": "verdictan-proxy",
                "service": &self.service_name,
                "message": serde_json::to_string(event).unwrap_or_default(),
            }]);

            let client = super::http_client::shared_gateway_http_client()
                .map_err(|error| format!("gateway HTTP client: {error}"))?;
            let resp = client
                .post(&url)
                .header("DD-API-KEY", &self.api_key)
                .header("Content-Type", "application/json")
                .json(&body)
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await
                .map_err(|e| format!("datadog send error: {e}"))?;

            if !resp.status().is_success() {
                return Err(format!("datadog HTTP {}", resp.status()));
            }
            Ok(())
        })
    }

    fn name(&self) -> &'static str {
        "datadog"
    }
}

// ---------------------------------------------------------------------------
// Prometheus (metrics collection state — scrape-ready)
// ---------------------------------------------------------------------------

/// Collects Prometheus-style metrics from callback events with per-model and
/// per-provider label dimensions.
/// Use `render` to produce the text exposition for `/metrics`.
#[derive(Debug)]
pub struct PrometheusCallback {
    requests_total: std::sync::atomic::AtomicU64,
    tokens_total: std::sync::atomic::AtomicU64,
    cost_millionths: std::sync::atomic::AtomicU64,
    latency_sum_ms: std::sync::atomic::AtomicU64,
    /// Per-model request counters.
    per_model_requests: std::sync::Mutex<HashMap<String, u64>>,
    /// Per-provider request counters.
    per_provider_requests: std::sync::Mutex<HashMap<String, u64>>,
}

impl PrometheusCallback {
    pub fn new() -> Self {
        Self {
            requests_total: std::sync::atomic::AtomicU64::new(0),
            tokens_total: std::sync::atomic::AtomicU64::new(0),
            cost_millionths: std::sync::atomic::AtomicU64::new(0),
            latency_sum_ms: std::sync::atomic::AtomicU64::new(0),
            per_model_requests: std::sync::Mutex::new(HashMap::new()),
            per_provider_requests: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Render Prometheus text exposition format for scraping.
    pub fn render(&self) -> String {
        use std::fmt::Write;
        let reqs = self
            .requests_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let toks = self.tokens_total.load(std::sync::atomic::Ordering::Relaxed);
        let cost = self
            .cost_millionths
            .load(std::sync::atomic::Ordering::Relaxed) as f64
            / 1_000_000.0;
        let lat = self
            .latency_sum_ms
            .load(std::sync::atomic::Ordering::Relaxed) as f64
            / 1_000.0;
        let mut out = format!(
            "# HELP verdictan_llm_requests_total Total LLM requests proxied.\n\
             # TYPE verdictan_llm_requests_total counter\n\
             verdictan_llm_requests_total {reqs}\n\
             # HELP verdictan_llm_tokens_total Total tokens consumed.\n\
             # TYPE verdictan_llm_tokens_total counter\n\
             verdictan_llm_tokens_total {toks}\n\
             # HELP verdictan_llm_cost_total Total cost in USD.\n\
             # TYPE verdictan_llm_cost_total counter\n\
             verdictan_llm_cost_total {cost}\n\
             # HELP verdictan_llm_latency_seconds_sum Sum of latency in seconds.\n\
             # TYPE verdictan_llm_latency_seconds_sum counter\n\
             verdictan_llm_latency_seconds_sum {lat}\n"
        );

        // Per-model breakdown.
        if let Ok(models) = self.per_model_requests.lock() {
            if !models.is_empty() {
                out.push_str("# HELP verdictan_llm_requests_by_model Total requests by model.\n");
                out.push_str("# TYPE verdictan_llm_requests_by_model counter\n");
                let mut sorted: Vec<_> = models.iter().collect();
                sorted.sort_by_key(|(k, _)| (*k).clone());
                for (model, count) in sorted {
                    let _ = writeln!(
                        out,
                        "verdictan_llm_requests_by_model{{model=\"{model}\"}} {count}"
                    );
                }
            }
        }

        // Per-provider breakdown.
        if let Ok(providers) = self.per_provider_requests.lock() {
            if !providers.is_empty() {
                out.push_str(
                    "# HELP verdictan_llm_requests_by_provider Total requests by provider.\n",
                );
                out.push_str("# TYPE verdictan_llm_requests_by_provider counter\n");
                let mut sorted: Vec<_> = providers.iter().collect();
                sorted.sort_by_key(|(k, _)| (*k).clone());
                for (provider, count) in sorted {
                    let _ = writeln!(
                        out,
                        "verdictan_llm_requests_by_provider{{provider=\"{provider}\"}} {count}"
                    );
                }
            }
        }

        out
    }
}

impl Default for PrometheusCallback {
    fn default() -> Self {
        Self::new()
    }
}

impl CallbackSink for PrometheusCallback {
    fn send<'a>(
        &'a self,
        event: &'a CallbackEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        use std::sync::atomic::Ordering::Relaxed;
        self.requests_total.fetch_add(1, Relaxed);
        self.tokens_total
            .fetch_add(event.prompt_tokens + event.completion_tokens, Relaxed);
        // Store cost as integer millionths to avoid floating-point atomics.
        let cost_m = (event.cost * 1_000_000.0).round() as u64;
        self.cost_millionths.fetch_add(cost_m, Relaxed);
        self.latency_sum_ms.fetch_add(event.latency_ms, Relaxed);

        // Per-model counter.
        if !event.model.is_empty() {
            if let Ok(mut models) = self.per_model_requests.lock() {
                *models.entry(event.model.clone()).or_insert(0) += 1;
            }
        }
        // Per-provider counter.
        if !event.provider.is_empty() {
            if let Ok(mut providers) = self.per_provider_requests.lock() {
                *providers.entry(event.provider.clone()).or_insert(0) += 1;
            }
        }

        Box::pin(std::future::ready(Ok(())))
    }

    fn name(&self) -> &'static str {
        "prometheus"
    }
}

// ---------------------------------------------------------------------------
// Helicone (header-injection style)
// ---------------------------------------------------------------------------

/// Helicone integration works by injecting the `Helicone-Auth` header into
/// proxied requests. The callback sink is a no-op logger; the actual header
/// injection happens in the proxy middleware layer.
#[derive(Debug, Clone)]
pub struct HeliconeCallback {
    pub api_key: String,
}

impl CallbackSink for HeliconeCallback {
    fn send<'a>(
        &'a self,
        event: &'a CallbackEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        tracing::debug!(
            request_id = %event.request_id,
            provider = %event.provider,
            "helicone: event logged (header injection is upstream)"
        );
        Box::pin(std::future::ready(Ok(())))
    }

    fn name(&self) -> &'static str {
        "helicone"
    }
}

// ---------------------------------------------------------------------------
// Braintrust
// ---------------------------------------------------------------------------

/// Sends events to the Braintrust logging API.
#[derive(Debug, Clone)]
pub struct BraintrustCallback {
    pub api_key: String,
    pub project_name: String,
}

impl CallbackSink for BraintrustCallback {
    fn send<'a>(
        &'a self,
        event: &'a CallbackEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let url = "https://api.braintrustdata.com/v1/insert";
            let body = serde_json::json!({
                "project_name": &self.project_name,
                "events": [{
                    "id": &event.request_id,
                    "input": { "provider": &event.provider, "model": &event.model },
                    "metrics": {
                        "prompt_tokens": event.prompt_tokens,
                        "completion_tokens": event.completion_tokens,
                        "cost": event.cost,
                        "latency_ms": event.latency_ms,
                    },
                    "metadata": &event.metadata,
                }]
            });

            let client = super::http_client::shared_gateway_http_client()
                .map_err(|error| format!("gateway HTTP client: {error}"))?;
            let resp = client
                .post(url)
                .bearer_auth(&self.api_key)
                .json(&body)
                .timeout(std::time::Duration::from_secs(5))
                .send()
                .await
                .map_err(|e| format!("braintrust send error: {e}"))?;

            if !resp.status().is_success() {
                return Err(format!("braintrust HTTP {}", resp.status()));
            }
            Ok(())
        })
    }

    fn name(&self) -> &'static str {
        "braintrust"
    }
}

// ---------------------------------------------------------------------------
// Callback router — fan-out to all configured sinks
// ---------------------------------------------------------------------------

/// Maximum number of configured callback sinks.
pub const MAX_CALLBACK_SINKS: usize = 32;

/// Destination kinds owned exclusively by the API SIEM adapters (ADR-020).
/// Rejected as callback `type` values so this legacy surface cannot be mistaken
/// for SIEM connector configuration. Legacy `datadog` callbacks remain distinct
/// from API-owned `datadog` SIEM destinations.
const REJECTED_SIEM_CALLBACK_TYPES: &[&str] = &[
    "splunk",
    "elastic",
    "generic_https_json",
    "splunk_hec",
    "datadog_logs",
];

fn is_rejected_siem_callback_type(cb_type: &str) -> bool {
    REJECTED_SIEM_CALLBACK_TYPES
        .iter()
        .any(|kind| kind.eq_ignore_ascii_case(cb_type))
}

/// Routes a `CallbackEvent` to all registered sinks.
pub struct CallbackRouter {
    pub sinks: Vec<Box<dyn CallbackSink>>,
    prom: Option<Arc<PrometheusCallback>>,
    /// Set during `from_json` when configuration is invalid (unknown type, too many sinks).
    pub load_error: Option<String>,
}

impl CallbackRouter {
    pub fn new(sinks: Vec<Box<dyn CallbackSink>>) -> Self {
        Self {
            sinks,
            prom: None,
            load_error: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }

    /// Return a shared `Arc<PrometheusCallback>` if one is registered.
    pub fn prometheus_sink(&self) -> Option<Arc<PrometheusCallback>> {
        self.prom.clone()
    }

    /// Fan out the event to every sink. Errors are logged, never propagated.
    pub async fn dispatch(&self, event: &CallbackEvent) {
        for sink in &self.sinks {
            if let Err(e) = sink.send(event).await {
                tracing::warn!(
                    callback = sink.name(),
                    error = %e,
                    "callback sink delivery failed"
                );
            }
        }
    }

    /// Privacy-aware dispatch: scrub the event before sending to sinks.
    async fn dispatch_with_privacy(
        &self,
        event: &CallbackEvent,
        turn_off_message_logging: bool,
        redact_user: bool,
    ) {
        let scrubbed = event.scrub_for_privacy(turn_off_message_logging, redact_user);
        self.dispatch(&scrubbed).await;
    }

    /// Parse the `callbacks` section of a declarative config.
    ///
    /// ```json
    /// { "callbacks": [ { "type": "langfuse", "host": "...",... } ] }
    /// ```
    pub fn from_json(root: &serde_json::Value) -> Self {
        let Some(arr) = root.get("callbacks").and_then(|v| v.as_array()) else {
            return Self {
                sinks: Vec::new(),
                prom: None,
                load_error: None,
            };
        };

        let mut sinks: Vec<Box<dyn CallbackSink>> = Vec::new();
        let mut prom_ref: Option<Arc<PrometheusCallback>> = None;

        for entry in arr {
            let Some(cb_type) = entry.get("type").and_then(|v| v.as_str()) else {
                continue;
            };
            if is_rejected_siem_callback_type(cb_type) {
                return Self {
                    sinks: Vec::new(),
                    prom: None,
                    load_error: Some(format!(
                        "callback type '{cb_type}' is an API-owned SIEM destination kind; \
                         configure it via ai-usage-stream destinations, not gateway callbacks"
                    )),
                };
            }
            match cb_type {
                "langfuse" => {
                    let host = entry
                        .get("host")
                        .and_then(|v| v.as_str())
                        .unwrap_or("https://cloud.langfuse.com")
                        .to_string();
                    let public_key = resolve_env_or_literal(entry, "public_key_env", "public_key");
                    let secret_key = resolve_env_or_literal(entry, "secret_key_env", "secret_key");
                    sinks.push(Box::new(LangfuseCallback {
                        host,
                        public_key,
                        secret_key,
                    }));
                }
                "datadog" => {
                    let api_key =
                        resolve_secret_key_ref_or_literal(entry, "secret_key_ref", "api_key");
                    let site = entry
                        .get("site")
                        .and_then(|v| v.as_str())
                        .unwrap_or("datadoghq.com")
                        .to_string();
                    let service_name = entry
                        .get("service_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("verdictan-proxy")
                        .to_string();
                    let tags = entry
                        .get("tags")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(ToString::to_string))
                                .collect()
                        })
                        .unwrap_or_default();
                    sinks.push(Box::new(DatadogCallback {
                        api_key,
                        site,
                        service_name,
                        tags,
                    }));
                }
                "prometheus" => {
                    let prom = Arc::new(PrometheusCallback::new());
                    prom_ref = Some(Arc::clone(&prom));
                    sinks.push(Box::new(ArcPrometheusSink(prom)));
                }
                "helicone" => {
                    let api_key =
                        resolve_secret_key_ref_or_literal(entry, "secret_key_ref", "api_key");
                    sinks.push(Box::new(HeliconeCallback { api_key }));
                }
                "braintrust" => {
                    let api_key =
                        resolve_secret_key_ref_or_literal(entry, "secret_key_ref", "api_key");
                    let project_name = entry
                        .get("project_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("default")
                        .to_string();
                    sinks.push(Box::new(BraintrustCallback {
                        api_key,
                        project_name,
                    }));
                }
                _ => {
                    return Self {
                        sinks: Vec::new(),
                        prom: None,
                        load_error: Some(format!(
                            "unknown callback type '{cb_type}'; supported: langfuse, datadog, prometheus, helicone, braintrust"
                        )),
                    };
                }
            }
        }

        if sinks.len() > MAX_CALLBACK_SINKS {
            return Self {
                sinks: Vec::new(),
                prom: None,
                load_error: Some(format!(
                    "too many callback sinks ({}, max {MAX_CALLBACK_SINKS})",
                    sinks.len()
                )),
            };
        }

        Self {
            sinks,
            prom: prom_ref,
            load_error: None,
        }
    }
}

/// Thin wrapper so `Arc<PrometheusCallback>` can be stored as `Box<dyn CallbackSink>`.
struct ArcPrometheusSink(Arc<PrometheusCallback>);

impl CallbackSink for ArcPrometheusSink {
    fn send<'a>(
        &'a self,
        event: &'a CallbackEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        self.0.send(event)
    }

    fn name(&self) -> &'static str {
        "prometheus"
    }
}

/// Resolve a value from either an environment variable (via `*_env` key)
/// or a literal string (via `literal_key`).
fn resolve_env_or_literal(entry: &serde_json::Value, env_key: &str, literal_key: &str) -> String {
    if let Some(env_name) = entry.get(env_key).and_then(|v| v.as_str()) {
        if let Ok(val) = std::env::var(env_name) {
            return val;
        }
    }
    entry
        .get(literal_key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn resolve_secret_key_ref_or_literal(
    entry: &serde_json::Value,
    secret_ref_key: &str,
    literal_key: &str,
) -> String {
    match parse_env_secret_key_name(entry.get(secret_ref_key), secret_ref_key) {
        Ok(Some(env_name)) => std::env::var(&env_name).unwrap_or_default(),
        Ok(None) => entry
            .get(literal_key)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        Err(error) => {
            tracing::warn!(
                error = %error,
                field = secret_ref_key,
                "invalid callback secret key reference"
            );
            entry
                .get(literal_key)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(
        dead_code,
        clippy::approx_constant,
        clippy::assertions_on_constants,
        clippy::assign_op_pattern,
        clippy::await_holding_lock,
        clippy::bool_assert_comparison,
        clippy::clone_on_copy,
        clippy::cloned_ref_to_slice_refs,
        clippy::const_is_empty,
        clippy::derivable_impls,
        clippy::err_expect,
        clippy::expect_fun_call,
        clippy::expect_used,
        clippy::field_reassign_with_default,
        clippy::large_enum_variant,
        clippy::len_zero,
        clippy::manual_contains,
        clippy::manual_range_contains,
        clippy::needless_borrow,
        clippy::needless_borrows_for_generic_args,
        clippy::panic,
        clippy::print_stderr,
        clippy::type_complexity,
        clippy::unnecessary_literal_unwrap,
        clippy::unnecessary_map_or,
        clippy::unwrap_used,
        clippy::useless_conversion,
        clippy::useless_vec,
        unused_imports,
        unused_macros,
        unused_mut,
        unused_variables,
        clippy::nonminimal_bool,
        clippy::overly_complex_bool_expr,
        clippy::needless_update,
        clippy::unnecessary_get_then_check
    )]
    use super::*;
    use crate::test_support;
    use serde_json::json;
    use serial_test::serial;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct RecordingSink {
        name: &'static str,
        events: Arc<Mutex<Vec<CallbackEvent>>>,
        fail: bool,
    }

    impl RecordingSink {
        fn new(name: &'static str) -> (Self, Arc<Mutex<Vec<CallbackEvent>>>) {
            let events = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    name,
                    events: Arc::clone(&events),
                    fail: false,
                },
                events,
            )
        }

        fn failing(name: &'static str) -> Self {
            Self {
                name,
                events: Arc::new(Mutex::new(Vec::new())),
                fail: true,
            }
        }
    }

    impl CallbackSink for RecordingSink {
        fn send<'a>(
            &'a self,
            event: &'a CallbackEvent,
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
            Box::pin(async move {
                self.events.lock().expect("events lock").push(event.clone());
                if self.fail {
                    Err(format!("{} failed", self.name))
                } else {
                    Ok(())
                }
            })
        }

        fn name(&self) -> &'static str {
            self.name
        }
    }

    #[test]
    #[serial]
    fn resolve_env_or_literal_prefers_env_var_when_present() {
        let _guard = test_support::env_lock().lock().expect("env lock");
        test_support::unset_var("VERDICTAN_CALLBACK_PUBLIC_KEY");
        test_support::set_var("VERDICTAN_CALLBACK_PUBLIC_KEY", "env-public-key");

        let entry = json!({
            "public_key_env": "VERDICTAN_CALLBACK_PUBLIC_KEY",
            "public_key": "literal-public-key"
        });

        assert_eq!(
            resolve_env_or_literal(&entry, "public_key_env", "public_key"),
            "env-public-key"
        );

        test_support::unset_var("VERDICTAN_CALLBACK_PUBLIC_KEY");
    }

    #[test]
    #[serial]
    fn resolve_env_or_literal_falls_back_to_literal_when_env_is_missing() {
        let _guard = test_support::env_lock().lock().expect("env lock");
        test_support::unset_var("VERDICTAN_CALLBACK_PUBLIC_KEY_MISSING");

        let entry = json!({
            "public_key_env": "VERDICTAN_CALLBACK_PUBLIC_KEY_MISSING",
            "public_key": "literal-public-key"
        });

        assert_eq!(
            resolve_env_or_literal(&entry, "public_key_env", "public_key"),
            "literal-public-key"
        );
    }

    #[test]
    #[serial]
    fn resolve_secret_key_ref_or_literal_reads_env_secret_refs() {
        let _guard = test_support::env_lock().lock().expect("env lock");
        test_support::unset_var("VERDICTAN_CALLBACK_API_KEY");
        test_support::set_var("VERDICTAN_CALLBACK_API_KEY", "env-api-key");

        let entry = json!({
            "secret_key_ref": { "env": "VERDICTAN_CALLBACK_API_KEY" },
            "api_key": "literal-api-key"
        });

        assert_eq!(
            resolve_secret_key_ref_or_literal(&entry, "secret_key_ref", "api_key"),
            "env-api-key"
        );

        test_support::unset_var("VERDICTAN_CALLBACK_API_KEY");
    }

    #[test]
    #[serial]
    fn resolve_secret_key_ref_or_literal_returns_empty_when_env_ref_is_unset() {
        let _guard = test_support::env_lock().lock().expect("env lock");
        test_support::unset_var("VERDICTAN_CALLBACK_API_KEY_UNSET");

        let entry = json!({
            "secret_key_ref": { "env": "VERDICTAN_CALLBACK_API_KEY_UNSET" },
            "api_key": "literal-api-key"
        });

        assert_eq!(
            resolve_secret_key_ref_or_literal(&entry, "secret_key_ref", "api_key"),
            ""
        );
    }

    #[test]
    fn resolve_secret_key_ref_or_literal_falls_back_to_literal_for_store_refs() {
        let entry = json!({
            "secret_key_ref": { "store": "shared-secret" },
            "api_key": "literal-api-key"
        });

        assert_eq!(
            resolve_secret_key_ref_or_literal(&entry, "secret_key_ref", "api_key"),
            "literal-api-key"
        );
    }

    #[test]
    fn resolve_secret_key_ref_or_literal_falls_back_to_literal_for_invalid_refs() {
        let entry = json!({
            "secret_key_ref": {
                "env": "VERDICTAN_CALLBACK_API_KEY",
                "store": "shared-secret"
            },
            "api_key": "literal-api-key"
        });

        assert_eq!(
            resolve_secret_key_ref_or_literal(&entry, "secret_key_ref", "api_key"),
            "literal-api-key"
        );
    }

    fn sample_event() -> CallbackEvent {
        CallbackEvent {
            request_id: "req-1".to_string(),
            provider: "openai".to_string(),
            model: "gpt-4".to_string(),
            prompt_tokens: 100,
            completion_tokens: 50,
            cost: 0.015,
            latency_ms: 250,
            status: 200,
            cache_hit: false,
            metadata: {
                let mut m = HashMap::new();
                m.insert("prompt".to_string(), "hello".to_string());
                m.insert("completion".to_string(), "world".to_string());
                m.insert("user".to_string(), "alice".to_string());
                m
            },
            message_logging_enabled: true,
            user_redacted: false,
            key_id: Some("key-1".to_string()),
            user_id: Some("user-1".to_string()),
            team_id: Some("team-1".to_string()),
            budget_remaining: Some(100.0),
            budget_limit: Some(500.0),
            identity_assertion_kind: "api_token".to_string(),
            grant_actions: vec!["chat:completions".to_string()],
            session_id: Some("sess-1".to_string()),
        }
    }

    #[test]
    fn scrub_for_privacy_disables_message_logging() {
        let event = sample_event();
        let scrubbed = event.scrub_for_privacy(true, false);
        assert!(!scrubbed.message_logging_enabled);
        assert!(!scrubbed.metadata.contains_key("prompt"));
        assert!(!scrubbed.metadata.contains_key("completion"));
        assert!(scrubbed.key_id.is_some());
    }

    #[test]
    fn scrub_for_privacy_enables_message_logging_when_not_turned_off() {
        let mut event = sample_event();
        event.message_logging_enabled = false;
        let scrubbed = event.scrub_for_privacy(false, false);
        assert!(scrubbed.message_logging_enabled);
        assert!(scrubbed.metadata.contains_key("prompt"));
    }

    #[test]
    fn scrub_for_privacy_redacts_user() {
        let event = sample_event();
        let scrubbed = event.scrub_for_privacy(false, true);
        assert!(scrubbed.user_redacted);
        assert!(!scrubbed.metadata.contains_key("user"));
        assert!(scrubbed.key_id.is_none());
        assert!(scrubbed.user_id.is_none());
        assert!(scrubbed.team_id.is_none());
        assert!(scrubbed.budget_remaining.is_none());
        assert!(scrubbed.budget_limit.is_none());
    }

    #[test]
    fn scrub_for_privacy_both_flags() {
        let event = sample_event();
        let scrubbed = event.scrub_for_privacy(true, true);
        assert!(!scrubbed.message_logging_enabled);
        assert!(scrubbed.user_redacted);
        assert!(scrubbed.key_id.is_none());
        assert!(!scrubbed.metadata.contains_key("prompt"));
        assert!(!scrubbed.metadata.contains_key("user"));
    }

    #[test]
    fn apply_payload_fidelity_full_keeps_everything() {
        let mut event = sample_event();
        event.apply_payload_fidelity("full");
        assert!(event.key_id.is_some());
        assert!(event.user_id.is_some());
        assert!(event.budget_remaining.is_some());
    }

    #[test]
    fn apply_payload_fidelity_identity_strips_budget() {
        let mut event = sample_event();
        event.apply_payload_fidelity("identity");
        assert!(event.key_id.is_some());
        assert!(event.user_id.is_some());
        assert!(event.budget_remaining.is_none());
        assert!(event.budget_limit.is_none());
    }

    #[test]
    fn apply_payload_fidelity_event_only_strips_identity_and_budget() {
        let mut event = sample_event();
        event.apply_payload_fidelity("event_only");
        assert!(event.key_id.is_none());
        assert!(event.user_id.is_none());
        assert!(event.team_id.is_none());
        assert!(event.budget_remaining.is_none());
        assert!(event.budget_limit.is_none());
        assert_eq!(event.identity_assertion_kind, "header_soft");
    }

    #[test]
    fn apply_payload_fidelity_unknown_treated_as_event_only() {
        let mut event = sample_event();
        event.apply_payload_fidelity("whatever");
        assert!(event.key_id.is_none());
        assert!(event.user_id.is_none());
    }

    #[tokio::test]
    async fn prometheus_callback_tracks_metrics() {
        let prom = PrometheusCallback::new();
        let event = sample_event();
        prom.send(&event).await.unwrap();

        let rendered = prom.render();
        assert!(rendered.contains("verdictan_llm_requests_total 1"));
        assert!(rendered.contains("verdictan_llm_tokens_total 150"));
        assert!(rendered.contains("verdictan_llm_requests_by_model{model=\"gpt-4\"}"));
        assert!(rendered.contains("verdictan_llm_requests_by_provider{provider=\"openai\"}"));
    }

    #[test]
    fn prometheus_callback_render_empty() {
        let prom = PrometheusCallback::new();
        let rendered = prom.render();
        assert!(rendered.contains("verdictan_llm_requests_total 0"));
        assert!(rendered.contains("verdictan_llm_tokens_total 0"));
    }

    #[test]
    fn prometheus_default_is_new() {
        let prom = PrometheusCallback::default();
        assert_eq!(prom.render(), PrometheusCallback::new().render());
    }

    #[test]
    fn callback_router_from_json_empty_config() {
        let config = json!({});
        let router = CallbackRouter::from_json(&config);
        assert!(router.is_empty());
        assert!(router.prometheus_sink().is_none());
    }

    #[test]
    fn callback_router_from_json_prometheus() {
        let config = json!({
            "callbacks": [
                { "type": "prometheus" }
            ]
        });
        let router = CallbackRouter::from_json(&config);
        assert!(!router.is_empty());
        assert!(router.prometheus_sink().is_some());
    }

    #[test]
    fn callback_router_from_json_helicone() {
        let config = json!({
            "callbacks": [
                { "type": "helicone", "api_key": "hel-key" }
            ]
        });
        let router = CallbackRouter::from_json(&config);
        assert_eq!(router.sinks.len(), 1);
        assert_eq!(router.sinks[0].name(), "helicone");
    }

    #[test]
    fn callback_router_from_json_braintrust() {
        let config = json!({
            "callbacks": [
                { "type": "braintrust", "api_key": "bt-key", "project_name": "my-proj" }
            ]
        });
        let router = CallbackRouter::from_json(&config);
        assert_eq!(router.sinks.len(), 1);
        assert_eq!(router.sinks[0].name(), "braintrust");
    }

    #[test]
    fn callback_router_from_json_langfuse() {
        let config = json!({
            "callbacks": [
                { "type": "langfuse", "public_key": "pk", "secret_key": "sk" }
            ]
        });
        let router = CallbackRouter::from_json(&config);
        assert_eq!(router.sinks.len(), 1);
        assert_eq!(router.sinks[0].name(), "langfuse");
    }

    #[test]
    fn callback_router_from_json_datadog() {
        let config = json!({
            "callbacks": [
                { "type": "datadog", "api_key": "dd-key" }
            ]
        });
        let router = CallbackRouter::from_json(&config);
        assert_eq!(router.sinks.len(), 1);
        assert_eq!(router.sinks[0].name(), "datadog");
    }

    #[test]
    fn callback_router_from_json_unknown_type_skipped() {
        let config = json!({
            "callbacks": [
                { "type": "unknown_service", "api_key": "key" }
            ]
        });
        let router = CallbackRouter::from_json(&config);
        assert!(router.is_empty());
    }

    #[test]
    fn callback_router_from_json_multiple_sinks() {
        let config = json!({
            "callbacks": [
                { "type": "prometheus" },
                { "type": "helicone", "api_key": "hel" },
                { "type": "braintrust", "api_key": "bt" }
            ]
        });
        let router = CallbackRouter::from_json(&config);
        assert_eq!(router.sinks.len(), 3);
        assert!(router.prometheus_sink().is_some());
    }

    #[test]
    fn callback_router_from_json_entry_without_type_skipped() {
        let config = json!({
            "callbacks": [
                { "api_key": "no-type" },
                { "type": "prometheus" }
            ]
        });
        let router = CallbackRouter::from_json(&config);
        assert_eq!(router.sinks.len(), 1);
    }

    #[test]
    fn callback_event_serialization() {
        let event = sample_event();
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["request_id"], "req-1");
        assert_eq!(json["provider"], "openai");
        assert_eq!(json["model"], "gpt-4");
        assert_eq!(json["prompt_tokens"], 100);
        assert_eq!(json["status"], 200);
        assert_eq!(json["identity_assertion_kind"], "api_token");
    }

    #[test]
    fn callback_event_skip_serializing_none_fields() {
        let mut event = sample_event();
        event.key_id = None;
        event.user_id = None;
        event.session_id = None;
        let json = serde_json::to_value(&event).unwrap();
        assert!(json.get("key_id").is_none());
        assert!(json.get("user_id").is_none());
        assert!(json.get("session_id").is_none());
    }

    // ── scrub_for_privacy ───────────────────────────────────────────────

    #[test]
    fn scrub_for_privacy_strips_messages() {
        let mut event = sample_event();
        event
            .metadata
            .insert("prompt".to_string(), "secret prompt".to_string());
        event
            .metadata
            .insert("completion".to_string(), "secret completion".to_string());
        event
            .metadata
            .insert("messages".to_string(), "msgs".to_string());

        let scrubbed = event.scrub_for_privacy(true, false);
        assert!(!scrubbed.message_logging_enabled);
        assert!(scrubbed.metadata.get("prompt").is_none());
        assert!(scrubbed.metadata.get("completion").is_none());
        assert!(scrubbed.metadata.get("messages").is_none());
    }

    #[test]
    fn scrub_for_privacy_redacts_user_and_key() {
        let mut event = sample_event();
        event.user_id = Some("user-123".to_string());
        event.key_id = Some("key-456".to_string());

        let scrubbed = event.scrub_for_privacy(false, true);
        assert!(scrubbed.user_redacted);
        assert!(scrubbed.user_id.is_none());
        assert!(scrubbed.key_id.is_none());
    }

    #[test]
    fn scrub_for_privacy_preserves_when_no_flags() {
        let event = sample_event();
        let scrubbed = event.scrub_for_privacy(false, false);
        assert_eq!(scrubbed.user_id, event.user_id);
        assert_eq!(scrubbed.message_logging_enabled, true);
    }

    // ── default_identity_assertion_kind ──────────────────────────────────

    #[test]
    fn default_identity_assertion_kind_value() {
        assert_eq!(default_identity_assertion_kind(), "header_soft");
    }

    // ── CallbackRouter is_empty ─────────────────────────────────────────

    #[test]
    fn callback_router_empty() {
        let router = CallbackRouter::from_json(&json!({}));
        assert!(router.is_empty());
    }

    #[test]
    fn callback_router_empty_callbacks_array() {
        let router = CallbackRouter::from_json(&json!({"callbacks": []}));
        assert!(router.is_empty());
    }

    // ── CallbackRouter prometheus_sink ───────────────────────────────────

    #[test]
    fn callback_router_prometheus_sink_absent() {
        let router = CallbackRouter::from_json(&json!({
            "callbacks": [{"type": "langfuse", "api_key": "key"}]
        }));
        assert!(router.prometheus_sink().is_none());
    }

    #[test]
    fn callback_router_prometheus_sink_present() {
        let router = CallbackRouter::from_json(&json!({
            "callbacks": [{"type": "prometheus"}]
        }));
        assert!(router.prometheus_sink().is_some());
    }

    // ── CallbackRouter with multiple sinks ────────────────────────────

    #[test]
    fn callback_router_multiple_sinks_with_prometheus() {
        let router = CallbackRouter::from_json(&json!({
            "callbacks": [
                {"type": "prometheus"},
                {"type": "langfuse", "api_key": "test-key"}
            ]
        }));
        assert!(!router.is_empty());
        assert!(router.prometheus_sink().is_some());
    }

    #[tokio::test]
    async fn callback_router_dispatch_delivers_to_all_sinks_even_when_one_fails() {
        let (healthy_sink, healthy_events) = RecordingSink::new("healthy");
        let (tail_sink, tail_events) = RecordingSink::new("tail");
        let router = CallbackRouter {
            sinks: vec![
                Box::new(healthy_sink),
                Box::new(RecordingSink::failing("failing")),
                Box::new(tail_sink),
            ],
            prom: None,
            load_error: None,
        };

        router.dispatch(&sample_event()).await;

        assert_eq!(healthy_events.lock().expect("healthy events").len(), 1);
        assert_eq!(tail_events.lock().expect("tail events").len(), 1);
    }

    #[tokio::test]
    async fn callback_router_dispatch_with_privacy_scrubs_before_delivery() {
        let (sink, events) = RecordingSink::new("privacy");
        let router = CallbackRouter {
            sinks: vec![Box::new(sink)],
            prom: None,
            load_error: None,
        };

        router
            .dispatch_with_privacy(&sample_event(), true, true)
            .await;

        let recorded = events.lock().expect("events lock");
        assert_eq!(recorded.len(), 1);
        let event = &recorded[0];
        assert!(!event.message_logging_enabled);
        assert!(event.user_redacted);
        assert!(event.key_id.is_none());
        assert!(!event.metadata.contains_key("prompt"));
        assert!(!event.metadata.contains_key("user"));
    }

    #[tokio::test]
    async fn arc_prometheus_sink_forwards_events() {
        let inner = Arc::new(PrometheusCallback::new());
        let sink = ArcPrometheusSink(Arc::clone(&inner));

        sink.send(&sample_event()).await.expect("send");

        let rendered = inner.render();
        assert!(rendered.contains("verdictan_llm_requests_total 1"));
        assert_eq!(sink.name(), "prometheus");
    }

    #[test]
    fn callback_router_new_has_no_prometheus_sink() {
        let (sink, _events) = RecordingSink::new("single");
        let router = CallbackRouter::new(vec![Box::new(sink)]);
        assert!(!router.is_empty());
        assert!(router.prometheus_sink().is_none());
    }
}
