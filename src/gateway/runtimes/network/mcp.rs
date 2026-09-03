// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::CliError;
use crate::gateway::tool_budget::ToolBudgetConfig;
use crate::gateway::tool_security::ToolSecurityConfig;
use crate::gateway::tool_validation::{
    evaluate_tool_action_before_dispatch, ToolActionContext, ToolActionPreDispatchDecision,
    ToolValidationConfig,
};

use super::VerdictanNetworkAdapterRuntime;

pub static MCP_RUNTIME: McpRuntime = McpRuntime;

pub struct McpRuntime;

const DEFAULT_MCP_BRIDGE_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_CONTAINMENT_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_MAX_CONCURRENT_CALLS: u32 = 5;
const DEFAULT_NETWORK_POLICY: &str = "egress_restricted";

fn default_protocol_version() -> String {
    "2026-03-26".to_string()
}

fn default_network_policy() -> String {
    DEFAULT_NETWORK_POLICY.to_string()
}

fn default_containment_timeout_ms() -> u64 {
    DEFAULT_CONTAINMENT_TIMEOUT_MS
}

fn default_max_concurrent_calls() -> u32 {
    DEFAULT_MAX_CONCURRENT_CALLS
}

/// Outbound network containment for the published `/mcp` bridge dispatch path.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct McpContainmentConfig {
    #[serde(default = "default_network_policy")]
    pub network_policy: String,
    #[serde(default = "default_containment_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_max_concurrent_calls")]
    pub max_concurrent_calls: u32,
}

impl Default for McpContainmentConfig {
    fn default() -> Self {
        Self {
            network_policy: default_network_policy(),
            timeout_ms: default_containment_timeout_ms(),
            max_concurrent_calls: default_max_concurrent_calls(),
        }
    }
}

/// Bridge configuration for the native MCP HTTP runtime (`providers.targets[].mcp`).
///
/// Unknown declarative fields are rejected (`deny_unknown_fields`) so unread MCP
/// knobs cannot be silently accepted. Containment, budget, validation, and
/// security fields are enforced on the actual `tools/call` dispatch path.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpBridgeConfig {
    #[serde(default = "default_protocol_version")]
    pub protocol_version: String,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub tool_validation: Option<ToolValidationConfig>,
    #[serde(default)]
    pub tool_security: Option<ToolSecurityConfig>,
    #[serde(default)]
    pub tool_budget: Option<ToolBudgetConfig>,
    #[serde(default)]
    pub containment: McpContainmentConfig,
}

impl Default for McpBridgeConfig {
    fn default() -> Self {
        Self {
            protocol_version: default_protocol_version(),
            session_id: None,
            tool_validation: None,
            tool_security: None,
            tool_budget: None,
            containment: McpContainmentConfig::default(),
        }
    }
}

/// Process-wide completed/failed counters for actual MCP tool actions.
#[derive(Debug, Default)]
pub struct McpToolActionMeters {
    completed: AtomicU64,
    failed: AtomicU64,
}

impl McpToolActionMeters {
    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.completed.load(Ordering::Relaxed),
            self.failed.load(Ordering::Relaxed),
        )
    }

    fn record_completed(&self) {
        self.completed.fetch_add(1, Ordering::Relaxed);
    }

    fn record_failed(&self) {
        self.failed.fetch_add(1, Ordering::Relaxed);
    }
}

pub static MCP_TOOL_ACTION_METERS: McpToolActionMeters = McpToolActionMeters {
    completed: AtomicU64::new(0),
    failed: AtomicU64::new(0),
};

static MCP_CONCURRENCY_LIMITERS: LazyLock<Mutex<HashMap<String, Arc<Semaphore>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn concurrency_semaphore(limiter_key: &str, max_concurrent_calls: u32) -> Arc<Semaphore> {
    let max = max_concurrent_calls.max(1) as usize;
    let mut guard = MCP_CONCURRENCY_LIMITERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    Arc::clone(
        guard
            .entry(format!("{limiter_key}:{max}"))
            .or_insert_with(|| Arc::new(Semaphore::new(max))),
    )
}

fn try_acquire_concurrency(
    limiter_key: &str,
    max_concurrent_calls: u32,
) -> Result<OwnedSemaphorePermit, CliError> {
    concurrency_semaphore(limiter_key, max_concurrent_calls)
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            CliError::user(format!(
                "mcp bridge blocked tool call: concurrency_limit max_concurrent_calls={max_concurrent_calls}"
            ))
        })
}

/// Acquire a concurrency permit for published `/mcp` tool dispatch.
pub fn acquire_tool_concurrency_permit(
    limiter_key: &str,
    max_concurrent_calls: u32,
) -> Result<OwnedSemaphorePermit, CliError> {
    try_acquire_concurrency(limiter_key, max_concurrent_calls)
}

/// Bind a completed/failed tool result to the original pre-dispatch decision.
pub fn bind_tool_action_result(
    response: Value,
    decision: &ToolActionPreDispatchDecision,
    outcome: &str,
) -> Value {
    bind_action_to_response(response, decision, outcome)
}

/// Record one completed published/bridge tool action.
pub fn record_tool_action_completed() {
    MCP_TOOL_ACTION_METERS.record_completed();
}

/// Record one failed published/bridge tool action.
pub fn record_tool_action_failed() {
    MCP_TOOL_ACTION_METERS.record_failed();
}

impl super::super::VerdictanRuntime for McpRuntime {
    fn runtime_id(&self) -> &'static str {
        "mcp"
    }

    fn validate_config(&self, config: &Value) -> Result<(), CliError> {
        let has_adapter = config
            .get("adapter_command")
            .and_then(Value::as_str)
            .map(str::trim)
            .is_some_and(|value| !value.is_empty());
        let has_base_url = config
            .get("base_url")
            .and_then(Value::as_str)
            .map(str::trim)
            .is_some_and(|value| !value.is_empty());

        if has_adapter || has_base_url {
            return Ok(());
        }

        Err(CliError::user(
            "mcp runtime requires base_url for the native HTTP bridge or adapter_command for an explicit adapter-backed bridge",
        ))
    }

    fn build_request(&self, config: &Value, input: &Value) -> Result<Value, CliError> {
        self.build_request_with_session(config, input, None)
    }

    fn execute(&self, config: &Value, request: &Value) -> Result<Value, CliError> {
        // Note: execute is only used in the adapter-backed path; the native bridge
        // path goes through the async reqwest provider pipeline directly.
        let response = self.execute_network_call(config, request)?;
        self.parse_network_response(&response)
    }

    fn translate_response(&self, response: &Value) -> Result<Value, CliError> {
        if response.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Ok(response.clone());
        }

        if let Some(error) = response.get("error") {
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("MCP upstream error");
            let code = error
                .get("code")
                .cloned()
                .unwrap_or_else(|| json!("mcp_error"));
            let mut translated = json!({
                "error": {
                    "message": message,
                    "type": "mcp_error",
                    "code": code,
                },
                "mcp": response,
            });
            if let Some(binding) = response.get("verdictan_mcp_action") {
                translated["verdictan_mcp_action"] = binding.clone();
            }
            return Ok(translated);
        }

        let result = response.get("result").cloned().unwrap_or(Value::Null);
        let content = extract_mcp_result_text(&result);
        let id = response
            .get("id")
            .map(mcp_id_fragment)
            .unwrap_or_else(|| "unknown".to_string());

        let mut translated = json!({
            "id": format!("chatcmpl-mcp-{id}"),
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": if content.is_empty() { Value::Null } else { Value::String(content) }
                },
                "finish_reason": "stop"
            }],
            "mcp": result,
        });
        if let Some(binding) = response.get("verdictan_mcp_action") {
            translated["verdictan_mcp_action"] = binding.clone();
        }
        Ok(translated)
    }

    fn default_path_template(&self) -> Option<&'static str> {
        Some("/mcp")
    }

    fn supports_tools(&self) -> bool {
        true
    }

    fn requires_model(&self) -> bool {
        false
    }

    fn auth_optional(&self) -> bool {
        true
    }
}

impl McpRuntime {
    /// Build an MCP request with request-scoped session metadata.
    ///
    /// For `tools/call`, pre-dispatch governance runs before the
    /// request is returned; a deny decision never reaches upstream `/mcp`.
    pub fn build_request_with_session(
        &self,
        config: &Value,
        input: &Value,
        session: Option<&McpSessionMeta>,
    ) -> Result<Value, CliError> {
        let bridge = parse_bridge_config(config)?;
        let mut request = normalize_mcp_request(input)?;
        let decision = govern_tool_call_before_dispatch(&bridge, &request, session)?;
        annotate_request(&mut request, &bridge, session, decision.as_ref());
        Ok(request)
    }
}

fn parse_bridge_config(config: &Value) -> Result<McpBridgeConfig, CliError> {
    config
        .get("mcp")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| CliError::user(format!("invalid mcp bridge config: {error}")))
        .map(|value| value.unwrap_or_default())
}

fn bridge_endpoint(config: &Value) -> Result<String, CliError> {
    let base_url = config
        .get("base_url")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::user("mcp runtime requires base_url for the native HTTP bridge")
        })?;
    MCP_RUNTIME.validate_endpoint(base_url)?;

    let path = config
        .get("path_template")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("/mcp");

    let normalized_path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };

    Ok(format!(
        "{}{normalized_path}",
        base_url.trim_end_matches('/')
    ))
}

fn bridge_timeout(config: &Value, bridge: &McpBridgeConfig) -> Duration {
    let containment_cap = bridge.containment.timeout_ms.max(1);
    let requested = config
        .get("timeout_ms")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_MCP_BRIDGE_TIMEOUT_MS)
        .max(1);
    Duration::from_millis(requested.min(containment_cap))
}

pub fn configured_headers(
    config: &Value,
) -> Result<Vec<(reqwest::header::HeaderName, reqwest::header::HeaderValue)>, CliError> {
    let Some(headers) = config.get("headers").and_then(Value::as_object) else {
        return Ok(Vec::new());
    };

    let mut resolved = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        let header_name =
            reqwest::header::HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
                CliError::user(format!("invalid mcp header name {name:?}: {error}"))
            })?;
        let header_value = value.as_str().ok_or_else(|| {
            CliError::user(format!(
                "invalid mcp header value for {name:?}: expected string"
            ))
        })?;
        let header_value =
            reqwest::header::HeaderValue::from_str(header_value).map_err(|error| {
                CliError::user(format!("invalid mcp header value for {name:?}: {error}"))
            })?;
        resolved.push((header_name, header_value));
    }

    Ok(resolved)
}

pub fn normalize_mcp_request(input: &Value) -> Result<Value, CliError> {
    if input.get("jsonrpc").and_then(Value::as_str) == Some("2.0") {
        return Ok(input.clone());
    }

    let tool_name = extract_tool_name(input).ok_or_else(|| {
        CliError::user("mcp runtime expects a JSON-RPC request or a tool_name/tool.name field")
    })?;
    let arguments = input
        .get("arguments")
        .cloned()
        .or_else(|| input.get("input").cloned())
        .unwrap_or_else(|| json!({}));

    Ok(json!({
        "jsonrpc": "2.0",
        "id": input.get("id").cloned().unwrap_or_else(|| json!("verdictan-mcp")),
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
        }
    }))
}

/// Drive an async future to completion from a synchronous bridge-policy context.
///
/// When inside a Tokio multi-thread runtime, `block_in_place` is used. When
/// inside a current-thread runtime, the future is driven on a scoped worker
/// thread (`block_in_place` is unavailable). When there is no ambient runtime
/// (e.g. plain `#[test]`), a temporary current-thread runtime is created.
fn block_on_sync<F>(f: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => match handle.runtime_flavor() {
            tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| handle.block_on(f))
            }
            _ => {
                // Current-thread (and unknown) flavors cannot use block_in_place.
                // Drive the future on a scoped worker with its own runtime so
                // callers may borrow non-'static locals.
                std::thread::scope(|scope| {
                    scope
                        .spawn(|| {
                            // BOOT: sync bridge worker for non-multi-thread ambient runtimes.
                            #[allow(clippy::expect_used)]
                            let runtime = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()
                                .expect("failed to build tokio runtime for sync bridge");
                            runtime.block_on(f)
                        })
                        .join()
                        .unwrap_or_else(|_| {
                            #[allow(clippy::panic)]
                            {
                                panic!("mcp sync bridge worker thread panicked")
                            }
                        })
                })
            }
        },
        Err(_) => {
            // BOOT: sync bridge requires a temporary Tokio runtime when no runtime is active.
            #[allow(clippy::expect_used)]
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build tokio runtime for sync bridge");
            runtime.block_on(f)
        }
    }
}

/// Evaluate pre-dispatch governance for a `tools/call` request.
///
/// Non-tool methods return `Ok(None)`. Tool calls return the allow decision or
/// an error when denied, so upstream `/mcp` dispatch never observes a deny.
pub fn govern_tool_call_before_dispatch(
    bridge: &McpBridgeConfig,
    request: &Value,
    session: Option<&McpSessionMeta>,
) -> Result<Option<ToolActionPreDispatchDecision>, CliError> {
    if request.get("method").and_then(Value::as_str) != Some("tools/call") {
        return Ok(None);
    }

    let ctx = resolve_tool_action_context(bridge, request, session)?;
    let validation = bridge.tool_validation.clone().unwrap_or_default();
    let security = bridge.tool_security.clone().unwrap_or_default();
    let budget = bridge.tool_budget.clone().unwrap_or_default();
    let decision = block_on_sync(async move {
        evaluate_tool_action_before_dispatch(&validation, &security, &budget, &ctx).await
    });
    if !decision.allowed {
        let reason = decision
            .reason
            .clone()
            .unwrap_or_else(|| "tool_action_denied".to_string());
        return Err(CliError::user(format!(
            "mcp bridge blocked tool call: {reason}"
        )));
    }
    Ok(Some(decision))
}

/// Backward-compatible wrapper that discards the allow decision payload.
fn enforce_bridge_policies(bridge: &McpBridgeConfig, request: &Value) -> Result<(), CliError> {
    govern_tool_call_before_dispatch(bridge, request, None).map(|_| ())
}

/// Enforce network containment for the published MCP bridge endpoint.
pub fn enforce_network_containment(
    bridge: &McpBridgeConfig,
    endpoint: &str,
) -> Result<(), CliError> {
    let policy = bridge
        .containment
        .network_policy
        .trim()
        .to_ascii_lowercase();
    match policy.as_str() {
        "unrestricted" => Ok(()),
        "egress_restricted" => {
            if endpoint.starts_with("https://") || is_loopback_http_url(endpoint) {
                Ok(())
            } else {
                Err(CliError::user(
                    "mcp bridge blocked tool call: network_policy=egress_restricted requires https:// or loopback http://",
                ))
            }
        }
        "isolated" => {
            if is_loopback_http_url(endpoint) || is_loopback_https_url(endpoint) {
                Ok(())
            } else {
                Err(CliError::user(
                    "mcp bridge blocked tool call: network_policy=isolated requires loopback endpoint",
                ))
            }
        }
        other => Err(CliError::user(format!(
            "mcp bridge containment.network_policy must be one of: unrestricted, egress_restricted, isolated (got {other})"
        ))),
    }
}

fn is_loopback_http_url(endpoint: &str) -> bool {
    host_is_loopback(endpoint.strip_prefix("http://").unwrap_or(""))
}

fn is_loopback_https_url(endpoint: &str) -> bool {
    host_is_loopback(endpoint.strip_prefix("https://").unwrap_or(""))
}

fn host_is_loopback(remainder: &str) -> bool {
    if remainder.is_empty() {
        return false;
    }
    let authority = remainder.split('/').next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(ipv6_host) = host
        .strip_prefix('[')
        .and_then(|value| value.split(']').next())
    {
        return ipv6_host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    }
    let host = host.split(':').next().unwrap_or_default();
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn resolve_tool_action_context(
    bridge: &McpBridgeConfig,
    request: &Value,
    session: Option<&McpSessionMeta>,
) -> Result<ToolActionContext, CliError> {
    let tool_name = request
        .pointer("/params/name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::user("mcp tools/call requests require params.name"))?
        .to_string();
    let arguments = request
        .pointer("/params/arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let meta = request.pointer("/params/_meta");
    let authenticated_actor = session
        .and_then(|value| value.authenticated_actor.clone())
        .or_else(|| session.and_then(|value| value.agent_id.clone()))
        .or_else(|| {
            meta.and_then(|value| {
                value
                    .get("verdictan_authenticated_actor")
                    .or_else(|| value.get("verdictan_agent_id"))
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
            })
        })
        .or_else(|| bridge.session_id.clone())
        .unwrap_or_else(|| "mcp:unbound".to_string());

    let target_server = session
        .and_then(|value| value.target_server.clone())
        .or_else(|| {
            meta.and_then(|value| {
                value
                    .get("verdictan_target_server")
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
            })
        })
        .unwrap_or_else(|| "mcp:bridge".to_string());

    let remaining_action_budget = session
        .and_then(|value| value.remaining_action_budget)
        .or_else(|| {
            meta.and_then(|value| {
                value
                    .get("verdictan_remaining_action_budget")
                    .and_then(Value::as_u64)
            })
        })
        .or_else(|| {
            bridge
                .tool_budget
                .as_ref()
                .and_then(|budget| budget.budgets.get(&tool_name))
                .and_then(|limit| limit.max_calls)
        })
        .unwrap_or(u64::MAX);

    Ok(ToolActionContext {
        tool_name,
        arguments,
        authenticated_actor,
        target_server,
        remaining_action_budget,
    })
}

fn action_binding_value(
    decision: &ToolActionPreDispatchDecision,
    outcome: &str,
    completed: u64,
    failed: u64,
) -> Value {
    json!({
        "decision": if decision.allowed { "allow" } else { "deny" },
        "reason": decision.reason,
        "argument_digest": decision.argument_digest,
        "tool_name": decision.tool_name,
        "authenticated_actor": decision.authenticated_actor,
        "target_server": decision.target_server,
        "remaining_action_budget": decision.remaining_action_budget,
        "outcome": outcome,
        "tools_completed": completed,
        "tools_failed": failed,
        "evidence": decision.evidence,
    })
}

fn bind_action_to_response(
    mut response: Value,
    decision: &ToolActionPreDispatchDecision,
    outcome: &str,
) -> Value {
    let (completed, failed) = MCP_TOOL_ACTION_METERS.snapshot();
    if let Some(object) = response.as_object_mut() {
        object.insert(
            "verdictan_mcp_action".to_string(),
            action_binding_value(decision, outcome, completed, failed),
        );
    }
    response
}

#[derive(Clone, Debug, Default)]
pub struct McpSessionMeta {
    pub session_id: Option<String>,
    pub conversation_id: Option<String>,
    pub agent_id: Option<String>,
    pub authenticated_actor: Option<String>,
    pub target_server: Option<String>,
    pub remaining_action_budget: Option<u64>,
}

fn annotate_request(
    request: &mut Value,
    bridge: &McpBridgeConfig,
    session: Option<&McpSessionMeta>,
    decision: Option<&ToolActionPreDispatchDecision>,
) {
    let Some(params) = request.get_mut("params").and_then(Value::as_object_mut) else {
        return;
    };
    let meta = params
        .entry("_meta".to_string())
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    let Some(meta_object) = meta.as_object_mut() else {
        return;
    };
    meta_object.insert(
        "verdictan_protocol_version".to_string(),
        Value::String(bridge.protocol_version.clone()),
    );
    // Prefer request-scoped session metadata over static YAML config
    if let Some(session) = session {
        if let Some(ref sid) = session.session_id {
            meta_object.insert(
                "verdictan_session_id".to_string(),
                Value::String(sid.clone()),
            );
        } else if let Some(ref sid) = bridge.session_id {
            meta_object.insert(
                "verdictan_session_id".to_string(),
                Value::String(sid.clone()),
            );
        }
        if let Some(ref cid) = session.conversation_id {
            meta_object.insert(
                "verdictan_conversation_id".to_string(),
                Value::String(cid.clone()),
            );
        }
        if let Some(ref aid) = session.agent_id {
            meta_object.insert("verdictan_agent_id".to_string(), Value::String(aid.clone()));
        }
        if let Some(ref actor) = session.authenticated_actor {
            meta_object.insert(
                "verdictan_authenticated_actor".to_string(),
                Value::String(actor.clone()),
            );
        } else if let Some(ref aid) = session.agent_id {
            meta_object
                .entry("verdictan_authenticated_actor".to_string())
                .or_insert_with(|| Value::String(aid.clone()));
        }
        if let Some(ref target) = session.target_server {
            meta_object.insert(
                "verdictan_target_server".to_string(),
                Value::String(target.clone()),
            );
        }
        if let Some(budget) = session.remaining_action_budget {
            meta_object.insert(
                "verdictan_remaining_action_budget".to_string(),
                json!(budget),
            );
        }
    } else if let Some(ref sid) = bridge.session_id {
        meta_object.insert(
            "verdictan_session_id".to_string(),
            Value::String(sid.clone()),
        );
    }

    if let Some(decision) = decision {
        meta_object.insert(
            "verdictan_argument_digest".to_string(),
            Value::String(decision.argument_digest.clone()),
        );
        meta_object.insert(
            "verdictan_authenticated_actor".to_string(),
            Value::String(decision.authenticated_actor.clone()),
        );
        meta_object.insert(
            "verdictan_target_server".to_string(),
            Value::String(decision.target_server.clone()),
        );
        meta_object.insert(
            "verdictan_pre_dispatch_decision".to_string(),
            Value::String("allow".to_string()),
        );
    }
}

fn extract_tool_name(input: &Value) -> Option<String> {
    input
        .get("tool_name")
        .and_then(Value::as_str)
        .or_else(|| input.get("name").and_then(Value::as_str))
        .or_else(|| input.pointer("/tool/name").and_then(Value::as_str))
        .or_else(|| input.pointer("/function/name").and_then(Value::as_str))
        .map(ToString::to_string)
}

fn extract_mcp_result_text(result: &Value) -> String {
    if let Some(text) = result.get("text").and_then(Value::as_str) {
        return text.to_string();
    }

    if let Some(content) = result.get("content").and_then(Value::as_array) {
        let pieces = content
            .iter()
            .filter_map(|item| {
                if let Some(text) = item.as_str() {
                    return Some(text.to_string());
                }
                item.get("text")
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
                    .or_else(|| {
                        item.get("content")
                            .and_then(Value::as_str)
                            .map(ToString::to_string)
                    })
            })
            .collect::<Vec<_>>();
        if !pieces.is_empty() {
            return pieces.join("\n");
        }
    }

    result
        .get("structuredContent")
        .filter(|value| !value.is_null())
        .map(Value::to_string)
        .unwrap_or_default()
}

fn mcp_id_fragment(id: &Value) -> String {
    id.as_str()
        .map(ToString::to_string)
        .unwrap_or_else(|| id.to_string())
        .replace('"', "")
}

impl VerdictanNetworkAdapterRuntime for McpRuntime {
    fn adapter_id(&self) -> &'static str {
        "mcp"
    }

    fn validate_endpoint(&self, endpoint: &str) -> Result<(), CliError> {
        if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
            return Ok(());
        }
        Err(CliError::user(
            "mcp runtime requires a base_url starting with http:// or https://",
        ))
    }

    fn serialize_request(&self, request: &Value) -> Result<Value, CliError> {
        Ok(request.clone())
    }

    fn execute_network_call(&self, config: &Value, request: &Value) -> Result<Value, CliError> {
        let bridge = parse_bridge_config(config)?;
        let endpoint = bridge_endpoint(config)?;
        enforce_network_containment(&bridge, &endpoint)?;

        // Re-evaluate immediately before dispatch; deny never reaches /mcp.
        let decision = govern_tool_call_before_dispatch(&bridge, request, None)?;
        let is_tool_call = request.get("method").and_then(Value::as_str) == Some("tools/call");
        let _permit = if is_tool_call {
            Some(try_acquire_concurrency(
                &endpoint,
                bridge.containment.max_concurrent_calls,
            )?)
        } else {
            None
        };

        let timeout = bridge_timeout(config, &bridge);
        let headers = configured_headers(config)?;
        let request_body = serde_json::to_vec(request)
            .map_err(|error| CliError::user(format!("failed to serialize mcp request: {error}")))?;

        // Use block_in_place so we can drive async reqwest from this synchronous trait
        // method without nesting a second Tokio runtime.
        let response = tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async {
                let client = reqwest::Client::builder()
                    .timeout(timeout)
                    .build()
                    .map_err(|error| {
                        CliError::network(format!("failed to build mcp bridge client: {error}"))
                    })?;

                let resp = tokio::time::timeout(timeout, async {
                    let mut request_builder = client
                        .post(&endpoint)
                        .header(reqwest::header::ACCEPT, "application/json")
                        .header(reqwest::header::CONTENT_TYPE, "application/json");
                    for (name, value) in &headers {
                        request_builder = request_builder.header(name, value);
                    }
                    request_builder.body(request_body).send().await
                })
                .await
                .map_err(|_| CliError::network("mcp bridge request timed out".to_string()))?
                .map_err(|error| {
                    CliError::network(format!("mcp bridge request failed: {error}"))
                })?;

                let status = resp.status();
                let body = resp.text().await.map_err(|error| {
                    CliError::network(format!("failed to read mcp bridge response body: {error}"))
                })?;
                let parsed = serde_json::from_str::<Value>(&body).map_err(|error| {
                    CliError::network(format!(
                        "mcp bridge returned non-JSON response (status={status}): {error}"
                    ))
                })?;

                if !status.is_success() && parsed.get("jsonrpc").is_none() {
                    return Err(CliError::network(format!(
                        "mcp bridge returned HTTP {status}: {body}"
                    )));
                }

                Ok::<Value, CliError>(parsed)
            })
        });

        match (response, decision) {
            (Ok(parsed), Some(decision)) => {
                let tool_failed = parsed.get("error").is_some();
                if tool_failed {
                    MCP_TOOL_ACTION_METERS.record_failed();
                    Ok(bind_action_to_response(parsed, &decision, "failed"))
                } else {
                    MCP_TOOL_ACTION_METERS.record_completed();
                    Ok(bind_action_to_response(parsed, &decision, "completed"))
                }
            }
            (Ok(parsed), None) => Ok(parsed),
            (Err(error), Some(decision)) => {
                MCP_TOOL_ACTION_METERS.record_failed();
                let (completed, failed) = MCP_TOOL_ACTION_METERS.snapshot();
                Err(CliError::network(format!(
                    "{error} [mcp_action actor={} server={} digest={} decision=allow outcome=failed completed={completed} failed={failed}]",
                    decision.authenticated_actor,
                    decision.target_server,
                    decision.argument_digest,
                )))
            }
            (Err(error), None) => Err(error),
        }
    }

    fn parse_network_response(&self, response: &Value) -> Result<Value, CliError> {
        Ok(response.clone())
    }
}

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
    use crate::gateway::runtimes::{network::VerdictanNetworkAdapterRuntime, VerdictanRuntime};
    use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    async fn start_bridge_json_server(
        status: StatusCode,
        payload: Value,
    ) -> (
        String,
        Arc<Mutex<Vec<Vec<(String, String)>>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_for_handler = Arc::clone(&captured);
        let app = Router::new()
            .route(
                "/mcp",
                post(
                    move |State(captured): State<Arc<Mutex<Vec<Vec<(String, String)>>>>>,
                          headers: reqwest::header::HeaderMap| {
                        let payload = payload.clone();
                        async move {
                            let mut rendered = headers
                                .iter()
                                .filter_map(|(name, value)| {
                                    value
                                        .to_str()
                                        .ok()
                                        .map(|value| (name.as_str().to_string(), value.to_string()))
                                })
                                .collect::<Vec<_>>();
                            rendered.sort_unstable();
                            captured.lock().expect("captured headers").push(rendered);
                            (status, Json(payload))
                        }
                    },
                ),
            )
            .with_state(captured_for_handler);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind bridge server");
        let addr = listener.local_addr().expect("bridge addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve bridge");
        });

        (format!("http://{addr}"), captured, handle)
    }

    async fn start_bridge_text_server(
        status: StatusCode,
        body: &'static str,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new().route("/mcp", post(move || async move { (status, body) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind bridge server");
        let addr = listener.local_addr().expect("bridge addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve bridge");
        });

        (format!("http://{addr}"), handle)
    }

    #[test]
    fn runtime_id() {
        assert_eq!(MCP_RUNTIME.runtime_id(), "mcp");
    }

    #[test]
    fn adapter_id() {
        assert_eq!(MCP_RUNTIME.adapter_id(), "mcp");
    }

    #[test]
    fn validate_config_with_base_url() {
        let config = json!({"base_url": "https://mcp.example.com"});
        assert!(MCP_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_with_adapter_command() {
        let config = json!({"adapter_command": "/usr/bin/mcp-adapter"});
        assert!(MCP_RUNTIME.validate_config(&config).is_ok());
    }

    #[test]
    fn validate_config_missing_both() {
        assert!(MCP_RUNTIME.validate_config(&json!({})).is_err());
        assert!(MCP_RUNTIME
            .validate_config(&json!({"base_url": ""}))
            .is_err());
    }

    #[test]
    fn validate_endpoint_http() {
        assert!(MCP_RUNTIME
            .validate_endpoint("http://localhost:3000")
            .is_ok());
    }

    #[test]
    fn validate_endpoint_https() {
        assert!(MCP_RUNTIME
            .validate_endpoint("https://mcp.example.com")
            .is_ok());
    }

    #[test]
    fn validate_endpoint_other_scheme_rejected() {
        assert!(MCP_RUNTIME.validate_endpoint("ftp://example.com").is_err());
    }

    #[test]
    fn default_path_template_value() {
        assert_eq!(MCP_RUNTIME.default_path_template(), Some("/mcp"));
    }

    #[test]
    fn supports_tools_true() {
        assert!(MCP_RUNTIME.supports_tools());
    }

    #[test]
    fn requires_model_false() {
        assert!(!MCP_RUNTIME.requires_model());
    }

    #[test]
    fn auth_optional_true() {
        assert!(MCP_RUNTIME.auth_optional());
    }

    #[test]
    fn normalize_mcp_request_passthrough_jsonrpc() {
        let input = json!({"jsonrpc": "2.0", "method": "tools/call", "id": "1", "params": {}});
        let result = normalize_mcp_request(&input).unwrap();
        assert_eq!(result, input);
    }

    #[test]
    fn normalize_mcp_request_from_tool_name() {
        let input = json!({"tool_name": "search", "arguments": {"q": "rust"}});
        let result = normalize_mcp_request(&input).unwrap();
        assert_eq!(result["jsonrpc"], "2.0");
        assert_eq!(result["method"], "tools/call");
        assert_eq!(result["params"]["name"], "search");
        assert_eq!(result["params"]["arguments"]["q"], "rust");
    }

    #[test]
    fn normalize_mcp_request_from_name_field() {
        let input = json!({"name": "execute", "input": {"cmd": "ls"}});
        let result = normalize_mcp_request(&input).unwrap();
        assert_eq!(result["params"]["name"], "execute");
        assert_eq!(result["params"]["arguments"]["cmd"], "ls");
    }

    #[test]
    fn normalize_mcp_request_from_tool_nested_name() {
        let input = json!({"tool": {"name": "calculator"}, "arguments": {"expr": "2+2"}});
        let result = normalize_mcp_request(&input).unwrap();
        assert_eq!(result["params"]["name"], "calculator");
    }

    #[test]
    fn normalize_mcp_request_from_function_nested_name() {
        let input = json!({"function": {"name": "fetch"}, "arguments": {"url": "http://x"}});
        let result = normalize_mcp_request(&input).unwrap();
        assert_eq!(result["params"]["name"], "fetch");
    }

    #[test]
    fn normalize_mcp_request_missing_tool_name_errors() {
        let input = json!({"arguments": {"x": 1}});
        assert!(normalize_mcp_request(&input).is_err());
    }

    #[test]
    fn normalize_mcp_request_default_id() {
        let input = json!({"tool_name": "t"});
        let result = normalize_mcp_request(&input).unwrap();
        assert_eq!(result["id"], "verdictan-mcp");
    }

    #[test]
    fn normalize_mcp_request_preserves_id() {
        let input = json!({"tool_name": "t", "id": "custom-id"});
        let result = normalize_mcp_request(&input).unwrap();
        assert_eq!(result["id"], "custom-id");
    }

    #[test]
    fn build_request_with_session_normalizes_and_annotates_request() {
        let config = json!({
            "mcp": {
                "session_id": "bridge-session"
            }
        });
        let session = McpSessionMeta {
            session_id: Some("request-session".to_string()),
            conversation_id: Some("conv-42".to_string()),
            agent_id: Some("agent-7".to_string()),
            ..Default::default()
        };

        let request = MCP_RUNTIME
            .build_request_with_session(
                &config,
                &json!({"tool_name": "search", "arguments": {"q": "rust"}}),
                Some(&session),
            )
            .unwrap();

        assert_eq!(request["method"], "tools/call");
        assert_eq!(request["params"]["name"], "search");
        assert_eq!(request["params"]["arguments"]["q"], "rust");
        assert_eq!(
            request["params"]["_meta"]["verdictan_session_id"],
            "request-session"
        );
        assert_eq!(
            request["params"]["_meta"]["verdictan_conversation_id"],
            "conv-42"
        );
        assert_eq!(request["params"]["_meta"]["verdictan_agent_id"], "agent-7");
    }

    #[test]
    fn enforce_bridge_policies_skips_non_tool_call_requests() {
        let bridge = McpBridgeConfig {
            tool_validation: Some(ToolValidationConfig {
                declared_tools: vec!["search".to_string()],
                ..Default::default()
            }),
            tool_security: Some(ToolSecurityConfig {
                blocked_patterns: vec!["rm -rf".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };

        assert!(enforce_bridge_policies(
            &bridge,
            &json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
        )
        .is_ok());
    }

    #[test]
    fn enforce_bridge_policies_requires_tool_name_for_tool_calls() {
        let error = enforce_bridge_policies(
            &McpBridgeConfig::default(),
            &json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"arguments": {"q": "rust"}}
            }),
        )
        .expect_err("missing params.name should fail");

        assert!(format!("{error}").contains("params.name"));
    }

    #[test]
    fn enforce_bridge_policies_reports_undeclared_tools() {
        let bridge = McpBridgeConfig {
            tool_validation: Some(ToolValidationConfig {
                declared_tools: vec!["search".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };

        let error = enforce_bridge_policies(
            &bridge,
            &json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "delete_file", "arguments": {"path": "/tmp/demo"}}
            }),
        )
        .expect_err("undeclared tool should fail validation");

        assert!(format!("{error}").contains("undeclared_tools:delete_file"));
    }

    #[test]
    fn enforce_bridge_policies_reports_invalid_schemas() {
        let mut schemas = std::collections::HashMap::new();
        schemas.insert("search".to_string(), json!({"type": "invalid_type_value"}));
        let bridge = McpBridgeConfig {
            tool_validation: Some(ToolValidationConfig {
                schemas,
                allow_undeclared: true,
                ..Default::default()
            }),
            ..Default::default()
        };

        let error = enforce_bridge_policies(
            &bridge,
            &json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "search", "arguments": {"q": "rust"}}
            }),
        )
        .expect_err("invalid schema should fail validation");

        assert!(
            format!("{error}").contains("invalid_arguments:search")
                || format!("{error}").contains("invalid schemas")
                || format!("{error}").contains("search")
        );
    }

    #[test]
    fn enforce_bridge_policies_reports_tool_security_reason() {
        let bridge = McpBridgeConfig {
            tool_security: Some(ToolSecurityConfig {
                blocked_patterns: vec!["/etc/passwd".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };

        let error = enforce_bridge_policies(
            &bridge,
            &json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "search",
                    "arguments": {"path": "/etc/passwd"},
                    "_meta": {
                        "verdictan_authenticated_actor": "actor:user-1",
                        "verdictan_target_server": "mcp:bridge"
                    }
                }
            }),
        )
        .expect_err("blocked tool request should fail security policy");

        assert!(format!("{error}").contains("matched_blocked_pattern:/etc/passwd"));
    }

    #[test]
    fn govern_tool_call_allows_and_returns_decision() {
        let bridge = McpBridgeConfig {
            tool_validation: Some(ToolValidationConfig {
                declared_tools: vec!["search".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let session = McpSessionMeta {
            agent_id: Some("actor:user-1".to_string()),
            authenticated_actor: Some("actor:user-1".to_string()),
            target_server: Some("tool-server:docs".to_string()),
            ..Default::default()
        };
        let decision = govern_tool_call_before_dispatch(
            &bridge,
            &json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "search",
                    "arguments": {"q": "rust"}
                }
            }),
            Some(&session),
        )
        .expect("allow decision")
        .expect("tools/call decision");
        assert!(decision.allowed);
        assert!(decision.argument_digest.starts_with("sha256:"));
        assert_eq!(decision.authenticated_actor, "actor:user-1");
        assert_eq!(decision.target_server, "tool-server:docs");
    }

    #[test]
    fn translate_response_non_jsonrpc_passthrough() {
        let resp = json!({"data": "hello"});
        let result = MCP_RUNTIME.translate_response(&resp).unwrap();
        assert_eq!(result, resp);
    }

    #[test]
    fn translate_response_jsonrpc_error() {
        let resp = json!({
            "jsonrpc": "2.0",
            "id": "1",
            "error": {"code": -32600, "message": "Invalid request"}
        });
        let result = MCP_RUNTIME.translate_response(&resp).unwrap();
        assert_eq!(result["error"]["message"], "Invalid request");
        assert_eq!(result["error"]["type"], "mcp_error");
    }

    #[test]
    fn translate_response_jsonrpc_success_text() {
        let resp = json!({
            "jsonrpc": "2.0",
            "id": "req-42",
            "result": {"text": "Hello from MCP"}
        });
        let result = MCP_RUNTIME.translate_response(&resp).unwrap();
        assert_eq!(result["object"], "chat.completion");
        assert_eq!(result["choices"][0]["message"]["content"], "Hello from MCP");
        assert_eq!(result["choices"][0]["finish_reason"], "stop");
        assert!(result["id"].as_str().unwrap().contains("mcp"));
    }

    #[test]
    fn translate_response_jsonrpc_success_content_array() {
        let resp = json!({
            "jsonrpc": "2.0",
            "id": 5,
            "result": {"content": [{"text": "line1"}, {"text": "line2"}]}
        });
        let result = MCP_RUNTIME.translate_response(&resp).unwrap();
        let content = result["choices"][0]["message"]["content"].as_str().unwrap();
        assert!(content.contains("line1"));
        assert!(content.contains("line2"));
    }

    #[test]
    fn translate_response_jsonrpc_success_null_result() {
        let resp = json!({
            "jsonrpc": "2.0",
            "id": "x",
            "result": null
        });
        let result = MCP_RUNTIME.translate_response(&resp).unwrap();
        assert!(result["choices"][0]["message"]["content"].is_null());
    }

    #[test]
    fn extract_mcp_result_text_from_text_field() {
        let result = json!({"text": "direct text"});
        assert_eq!(extract_mcp_result_text(&result), "direct text");
    }

    #[test]
    fn extract_mcp_result_text_from_content_array() {
        let result = json!({"content": [{"text": "a"}, {"text": "b"}]});
        assert_eq!(extract_mcp_result_text(&result), "a\nb");
    }

    #[test]
    fn extract_mcp_result_text_from_string_content() {
        let result = json!({"content": ["plain string"]});
        assert_eq!(extract_mcp_result_text(&result), "plain string");
    }

    #[test]
    fn extract_mcp_result_text_from_structured_content() {
        let result = json!({"structuredContent": {"type": "table", "data": [1]}});
        let text = extract_mcp_result_text(&result);
        assert!(text.contains("table"));
    }

    #[test]
    fn extract_mcp_result_text_empty_fallback() {
        let result = json!({"other": "value"});
        assert_eq!(extract_mcp_result_text(&result), "");
    }

    #[test]
    fn mcp_id_fragment_string() {
        assert_eq!(mcp_id_fragment(&json!("request-1")), "request-1");
    }

    #[test]
    fn mcp_id_fragment_number() {
        assert_eq!(mcp_id_fragment(&json!(42)), "42");
    }

    #[test]
    fn mcp_bridge_config_default() {
        let config = McpBridgeConfig::default();
        assert_eq!(config.protocol_version, "2026-03-26");
        assert!(config.session_id.is_none());
        assert!(config.tool_validation.is_none());
        assert!(config.tool_security.is_none());
        assert!(config.tool_budget.is_none());
        assert_eq!(config.containment.network_policy, "egress_restricted");
        assert_eq!(
            config.containment.timeout_ms,
            DEFAULT_CONTAINMENT_TIMEOUT_MS
        );
        assert_eq!(
            config.containment.max_concurrent_calls,
            DEFAULT_MAX_CONCURRENT_CALLS
        );
    }

    #[test]
    fn mcp_bridge_config_deserializes() {
        let json = json!({"protocol_version": "2025-01-01", "session_id": "sess-1"});
        let config: McpBridgeConfig = serde_json::from_value(json).unwrap();
        assert_eq!(config.protocol_version, "2025-01-01");
        assert_eq!(config.session_id.as_deref(), Some("sess-1"));
    }

    #[test]
    fn mcp_bridge_config_rejects_unread_fields() {
        let json = json!({
            "protocol_version": "2026-03-26",
            "legacy_unread_field": true
        });
        let error = serde_json::from_value::<McpBridgeConfig>(json)
            .expect_err("unread declarative MCP fields must be rejected");
        assert!(error.to_string().contains("legacy_unread_field"));
    }

    #[test]
    fn mcp_bridge_config_serializes() {
        let config = McpBridgeConfig::default();
        let json = serde_json::to_value(&config).unwrap();
        assert_eq!(json["protocol_version"], "2026-03-26");
        assert_eq!(json["containment"]["network_policy"], "egress_restricted");
    }

    #[test]
    fn bridge_endpoint_constructs_url() {
        let config = json!({"base_url": "https://mcp.example.com", "path_template": "/v1/bridge"});
        let endpoint = bridge_endpoint(&config).unwrap();
        assert_eq!(endpoint, "https://mcp.example.com/v1/bridge");
    }

    #[test]
    fn bridge_endpoint_default_path() {
        let config = json!({"base_url": "https://mcp.example.com"});
        let endpoint = bridge_endpoint(&config).unwrap();
        assert_eq!(endpoint, "https://mcp.example.com/mcp");
    }

    #[test]
    fn bridge_endpoint_trims_trailing_slash() {
        let config = json!({"base_url": "https://mcp.example.com/"});
        let endpoint = bridge_endpoint(&config).unwrap();
        assert_eq!(endpoint, "https://mcp.example.com/mcp");
    }

    #[test]
    fn bridge_endpoint_prepends_missing_leading_slash() {
        let config = json!({"base_url": "https://mcp.example.com", "path_template": "bridge"});
        let endpoint = bridge_endpoint(&config).unwrap();
        assert_eq!(endpoint, "https://mcp.example.com/bridge");
    }

    #[test]
    fn bridge_endpoint_missing_base_url_errors() {
        assert!(bridge_endpoint(&json!({})).is_err());
    }

    #[test]
    fn bridge_timeout_default() {
        let timeout = bridge_timeout(&json!({}), &McpBridgeConfig::default());
        assert_eq!(
            timeout,
            Duration::from_millis(DEFAULT_MCP_BRIDGE_TIMEOUT_MS)
        );
    }

    #[test]
    fn bridge_timeout_custom_capped_by_containment() {
        let bridge = McpBridgeConfig {
            containment: McpContainmentConfig {
                timeout_ms: 8_000,
                ..Default::default()
            },
            ..Default::default()
        };
        let timeout = bridge_timeout(&json!({"timeout_ms": 15000}), &bridge);
        assert_eq!(timeout, Duration::from_millis(8_000));
    }

    #[test]
    fn bridge_timeout_minimum_one() {
        let bridge = McpBridgeConfig {
            containment: McpContainmentConfig {
                timeout_ms: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let timeout = bridge_timeout(&json!({"timeout_ms": 0}), &bridge);
        assert_eq!(timeout, Duration::from_millis(1));
    }

    #[test]
    fn network_containment_egress_restricted_blocks_plain_http_remote() {
        let bridge = McpBridgeConfig::default();
        let error = enforce_network_containment(&bridge, "http://mcp.example.com/mcp")
            .expect_err("remote http should be blocked");
        assert!(format!("{error}").contains("egress_restricted"));
    }

    #[test]
    fn network_containment_isolated_allows_loopback_only() {
        let bridge = McpBridgeConfig {
            containment: McpContainmentConfig {
                network_policy: "isolated".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(enforce_network_containment(&bridge, "http://127.0.0.1:9/mcp").is_ok());
        assert!(enforce_network_containment(&bridge, "https://mcp.example.com/mcp").is_err());
    }

    #[test]
    fn concurrency_limit_blocks_when_permits_exhausted() {
        let key = "mcp-concurrency-test-key";
        let _held = try_acquire_concurrency(key, 1).expect("first permit");
        let error = try_acquire_concurrency(key, 1).expect_err("second permit must fail");
        assert!(format!("{error}").contains("concurrency_limit"));
    }

    #[test]
    fn configured_headers_empty_when_missing() {
        let headers = configured_headers(&json!({})).unwrap();
        assert!(headers.is_empty());
    }

    #[test]
    fn configured_headers_parses_valid_headers() {
        let config = json!({"headers": {"x-custom": "value1", "authorization": "Bearer tok"}});
        let headers = configured_headers(&config).unwrap();
        assert_eq!(headers.len(), 2);
    }

    #[test]
    fn configured_headers_invalid_name_errors() {
        let config = json!({"headers": {"invalid header name!": "value"}});
        assert!(configured_headers(&config).is_err());
    }

    #[test]
    fn configured_headers_non_string_value_errors() {
        let config = json!({"headers": {"x-num": 123}});
        assert!(configured_headers(&config).is_err());
    }

    #[test]
    fn configured_headers_invalid_value_errors() {
        let config = json!({"headers": {"x-custom": "line1\nline2"}});
        assert!(configured_headers(&config).is_err());
    }

    #[test]
    fn mcp_session_meta_default() {
        let meta = McpSessionMeta::default();
        assert!(meta.session_id.is_none());
        assert!(meta.conversation_id.is_none());
        assert!(meta.agent_id.is_none());
    }

    #[test]
    fn annotate_request_adds_protocol_version() {
        let bridge = McpBridgeConfig::default();
        let mut request = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "test", "arguments": {}}
        });
        annotate_request(&mut request, &bridge, None, None);
        let meta = &request["params"]["_meta"];
        assert_eq!(meta["verdictan_protocol_version"], "2026-03-26");
    }

    #[test]
    fn annotate_request_adds_session_from_bridge_config() {
        let bridge = McpBridgeConfig {
            session_id: Some("bridge-sess".to_string()),
            ..Default::default()
        };
        let mut request = json!({"params": {"name": "test"}});
        annotate_request(&mut request, &bridge, None, None);
        assert_eq!(
            request["params"]["_meta"]["verdictan_session_id"],
            "bridge-sess"
        );
    }

    #[test]
    fn annotate_request_session_meta_overrides_bridge() {
        let bridge = McpBridgeConfig {
            session_id: Some("bridge-sess".to_string()),
            ..Default::default()
        };
        let session = McpSessionMeta {
            session_id: Some("request-sess".to_string()),
            conversation_id: Some("conv-1".to_string()),
            agent_id: Some("agent-1".to_string()),
            ..Default::default()
        };
        let mut request = json!({"params": {"name": "test"}});
        annotate_request(&mut request, &bridge, Some(&session), None);
        let meta = &request["params"]["_meta"];
        assert_eq!(meta["verdictan_session_id"], "request-sess");
        assert_eq!(meta["verdictan_conversation_id"], "conv-1");
        assert_eq!(meta["verdictan_agent_id"], "agent-1");
    }

    #[test]
    fn annotate_request_no_params_is_noop() {
        let bridge = McpBridgeConfig::default();
        let mut request = json!({"jsonrpc": "2.0", "method": "ping"});
        annotate_request(&mut request, &bridge, None, None);
        assert!(request.get("params").is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn execute_network_call_includes_configured_headers() {
        let (base_url, captured, handle) = start_bridge_json_server(
            StatusCode::OK,
            json!({"jsonrpc": "2.0", "result": {"text": "ok"}}),
        )
        .await;
        let config = json!({
            "base_url": base_url,
            "headers": {
                "x-custom-auth": "bridge-token"
            },
            "mcp": {
                "containment": {
                    "network_policy": "isolated",
                    "timeout_ms": 5000,
                    "max_concurrent_calls": 2
                }
            }
        });

        let response = MCP_RUNTIME
            .execute_network_call(&config, &json!({"jsonrpc": "2.0", "method": "ping"}))
            .expect("bridge call should succeed");

        handle.abort();

        assert_eq!(response["result"]["text"], "ok");
        let captured = captured.lock().expect("captured headers");
        assert_eq!(captured.len(), 1);
        assert!(captured[0].contains(&("x-custom-auth".to_string(), "bridge-token".to_string())));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn execute_network_call_rejects_non_json_responses() {
        let (base_url, handle) = start_bridge_text_server(StatusCode::OK, "not-json").await;
        let config = json!({
            "base_url": base_url,
            "mcp": {
                "containment": {
                    "network_policy": "isolated",
                    "timeout_ms": 5000,
                    "max_concurrent_calls": 2
                }
            }
        });

        let error = MCP_RUNTIME
            .execute_network_call(&config, &json!({"jsonrpc": "2.0", "method": "ping"}))
            .expect_err("non-json bridge response should fail");

        handle.abort();

        assert!(format!("{error}").contains("non-JSON response"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn execute_network_call_surfaces_http_error_bodies() {
        let (base_url, _captured, handle) =
            start_bridge_json_server(StatusCode::BAD_GATEWAY, json!({"error": "boom"})).await;
        let config = json!({
            "base_url": base_url,
            "mcp": {
                "containment": {
                    "network_policy": "isolated",
                    "timeout_ms": 5000,
                    "max_concurrent_calls": 2
                }
            }
        });

        let error = MCP_RUNTIME
            .execute_network_call(&config, &json!({"jsonrpc": "2.0", "method": "ping"}))
            .expect_err("http bridge error should fail");

        handle.abort();

        assert!(format!("{error}").contains("HTTP 502 Bad Gateway"));
        assert!(format!("{error}").contains("boom"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deny_before_dispatch_never_reaches_published_mcp() {
        let (base_url, captured, handle) = start_bridge_json_server(
            StatusCode::OK,
            json!({"jsonrpc": "2.0", "result": {"text": "should-not-run"}}),
        )
        .await;
        let config = json!({
            "base_url": base_url,
            "mcp": {
                "tool_validation": {
                    "declared_tools": ["search"]
                },
                "containment": {
                    "network_policy": "isolated",
                    "timeout_ms": 5000,
                    "max_concurrent_calls": 1
                }
            }
        });
        let request = json!({
            "jsonrpc": "2.0",
            "id": "deny-1",
            "method": "tools/call",
            "params": {
                "name": "delete_file",
                "arguments": {"path": "/tmp/x"},
                "_meta": {
                    "verdictan_authenticated_actor": "actor:user-1",
                    "verdictan_target_server": "mcp:bridge"
                }
            }
        });

        let error = MCP_RUNTIME
            .execute_network_call(&config, &request)
            .expect_err("deny must fail closed before dispatch");

        handle.abort();

        assert!(format!("{error}").contains("undeclared_tools:delete_file"));
        assert!(captured.lock().expect("captured headers").is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn successful_tool_dispatch_binds_decision_identity_and_meters_completion() {
        let (base_url, _captured, handle) = start_bridge_json_server(
            StatusCode::OK,
            json!({"jsonrpc": "2.0", "id": "ok-1", "result": {"text": "done"}}),
        )
        .await;
        let config = json!({
            "base_url": base_url,
            "mcp": {
                "tool_validation": {
                    "declared_tools": ["search"]
                },
                "containment": {
                    "network_policy": "isolated",
                    "timeout_ms": 5000,
                    "max_concurrent_calls": 2
                }
            }
        });
        let before = MCP_TOOL_ACTION_METERS.snapshot();
        let mut request = MCP_RUNTIME
            .build_request_with_session(
                &config,
                &json!({
                    "tool_name": "search",
                    "arguments": {"q": "rust"},
                    "id": "ok-1"
                }),
                Some(&McpSessionMeta {
                    agent_id: Some("actor:user-9".to_string()),
                    session_id: Some("sess-9".to_string()),
                    ..Default::default()
                }),
            )
            .expect("allow build");
        if let Some(params) = request.get_mut("params").and_then(Value::as_object_mut) {
            let meta = params
                .entry("_meta".to_string())
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            if let Some(meta_object) = meta.as_object_mut() {
                meta_object.insert(
                    "verdictan_target_server".to_string(),
                    Value::String("tool-server:docs".to_string()),
                );
            }
        }

        let response = MCP_RUNTIME
            .execute_network_call(&config, &request)
            .expect("dispatch should succeed");

        handle.abort();

        let after = MCP_TOOL_ACTION_METERS.snapshot();
        assert_eq!(after.0, before.0 + 1);
        assert_eq!(after.1, before.1);
        assert_eq!(response["verdictan_mcp_action"]["outcome"], "completed");
        assert_eq!(
            response["verdictan_mcp_action"]["authenticated_actor"],
            "actor:user-9"
        );
        assert_eq!(
            response["verdictan_mcp_action"]["target_server"],
            "tool-server:docs"
        );
        assert_eq!(response["verdictan_mcp_action"]["decision"], "allow");
        assert!(response["verdictan_mcp_action"]["argument_digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));

        let translated = MCP_RUNTIME
            .translate_response(&response)
            .expect("translate");
        assert_eq!(translated["verdictan_mcp_action"]["outcome"], "completed");
    }

    #[test]
    fn extract_tool_name_from_various_fields() {
        assert_eq!(
            extract_tool_name(&json!({"tool_name": "a"})),
            Some("a".to_string())
        );
        assert_eq!(
            extract_tool_name(&json!({"name": "b"})),
            Some("b".to_string())
        );
        assert_eq!(
            extract_tool_name(&json!({"tool": {"name": "c"}})),
            Some("c".to_string())
        );
        assert_eq!(
            extract_tool_name(&json!({"function": {"name": "d"}})),
            Some("d".to_string())
        );
        assert_eq!(extract_tool_name(&json!({"other": "x"})), None);
    }

    #[test]
    fn parse_bridge_config_missing_returns_default() {
        let config = json!({});
        let bridge = parse_bridge_config(&config).unwrap();
        assert_eq!(bridge.protocol_version, "2026-03-26");
    }

    #[test]
    fn parse_bridge_config_invalid_errors() {
        let config = json!({"mcp": "not an object"});
        assert!(parse_bridge_config(&config).is_err());
    }
}
