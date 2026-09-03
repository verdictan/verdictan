// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Shared MCP JSON-RPC request handling reused by transport layers.

use serde_json::Value;

use crate::api::AsyncApiClient;
use crate::gateway::declarative_config::MatchListOrWildcard;
use crate::gateway::session::GatewaySessionContext;
use crate::mcp;

pub(crate) const MCP_PROTOCOL_VERSION: &str = "2026-03-26";
pub(crate) const MCP_SERVER_NAME: &str = "verdictan";
pub(crate) const MCP_SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpToolServerPolicy {
    pub allow_unapproved: bool,
    pub allowed_ids: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct McpSessionPolicy {
    pub allowed_tools: MatchListOrWildcard,
    pub allowed_resources: MatchListOrWildcard,
    pub max_prompt_bytes: u64,
    pub max_test_inference_cost_usd: Option<f64>,
    pub max_concurrent_sessions: u32,
    pub auth_mode: Option<String>,
    pub tool_servers: Option<McpToolServerPolicy>,
    // action governance applied immediately before published `/mcp` tool dispatch.
    pub action_bridge: crate::gateway::runtimes::network::mcp::McpBridgeConfig,
}

impl Default for McpSessionPolicy {
    fn default() -> Self {
        Self {
            allowed_tools: MatchListOrWildcard::Wildcard,
            allowed_resources: MatchListOrWildcard::Wildcard,
            max_prompt_bytes: u64::MAX,
            max_test_inference_cost_usd: None,
            max_concurrent_sessions: u32::MAX,
            auth_mode: None,
            tool_servers: None,
            action_bridge: crate::gateway::runtimes::network::mcp::McpBridgeConfig::default(),
        }
    }
}

impl McpSessionPolicy {
    pub fn allows_tool(&self, tool_name: &str) -> bool {
        crate::policy::evaluator::ToolAccessEvaluator::from_match_list(&self.allowed_tools)
            .allows(tool_name, None)
    }

    pub fn allows_resource(&self, uri: &str) -> bool {
        match &self.allowed_resources {
            MatchListOrWildcard::Wildcard => true,
            MatchListOrWildcard::Explicit(values) => values
                .iter()
                .any(|value| mcp::resources::resource_matches_allow_entry(value, uri)),
        }
    }
}

const CHAT_COMPARE_TOOL: &str = "chat_compare";
const CHAT_TEST_TOOL: &str = "chat_test";
const TOOL_SERVER_ACCESS_DENIED_CODE: &str = "tool_server.access_denied";
const TOOL_SERVER_ALLOWED_IDS_REMEDIATION: &str =
    "Request a permitted tool server or add its id to mcp.tool_servers.allowed_ids for this agent.";
const TOOL_SERVER_APPROVAL_REMEDIATION: &str =
    "Approve the tool server or explicitly allow unapproved access for this agent.";
const GATEWAY_TOOL_SERVERS_RESOURCE_URI: &str = "gateway://tool-servers";
const LEGACY_GATEWAY_TOOL_SERVERS_RESOURCE_URI: &str = "gateway-tool-servers://declared";

#[derive(Debug, Clone)]
struct ToolCallDenial {
    code: &'static str,
    message: String,
    remediation: Option<&'static str>,
}

#[derive(Clone)]
pub struct McpToolTraceContext {
    pub api_base_url: String,
    pub machine_client: reqwest::Client,
    pub session_context: GatewaySessionContext,
    pub traceparent: Option<String>,
}

impl McpToolServerPolicy {
    fn allows_tool_server(&self, tool_server: &Value) -> bool {
        self.denial_for_tool_server(tool_server).is_none()
    }

    fn denial_for_tool_server(&self, tool_server: &Value) -> Option<ToolCallDenial> {
        let identifier = tool_server
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .or_else(|| {
                tool_server
                    .get("name")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
            })
            .unwrap_or("unknown-tool-server");

        if !self.allowed_ids.is_empty() && !self.allowed_ids.iter().any(|value| value == identifier)
        {
            return Some(ToolCallDenial {
                code: TOOL_SERVER_ACCESS_DENIED_CODE,
                message: format!(
                    "MCP tool server '{identifier}' is not permitted for this session"
                ),
                remediation: Some(TOOL_SERVER_ALLOWED_IDS_REMEDIATION),
            });
        }

        let trust_state = tool_server
            .get("trust_state")
            .and_then(Value::as_str)
            .unwrap_or("pending");
        if !self.allow_unapproved && trust_state != "approved" {
            return Some(ToolCallDenial {
                code: TOOL_SERVER_ACCESS_DENIED_CODE,
                message: format!("MCP tool server '{identifier}' is not approved for this session"),
                remediation: Some(TOOL_SERVER_APPROVAL_REMEDIATION),
            });
        }

        None
    }
}

fn is_gateway_tool_servers_resource_uri(uri: &str) -> bool {
    [
        GATEWAY_TOOL_SERVERS_RESOURCE_URI,
        LEGACY_GATEWAY_TOOL_SERVERS_RESOURCE_URI,
    ]
    .into_iter()
    .any(|candidate| {
        uri == candidate
            || uri
                .strip_prefix(candidate)
                .is_some_and(|suffix| suffix.starts_with('?'))
    })
}

fn tool_call_denial_result(id: Value, denial: ToolCallDenial) -> Value {
    let text = match denial.remediation {
        Some(remediation) => format!("{}. Remediation: {remediation}", denial.message),
        None => denial.message.clone(),
    };
    jsonrpc_result(
        id,
        serde_json::json!({
            "structuredContent": {
                "ok": false,
                "error": {
                    "code": denial.code,
                    "message": denial.message,
                    "remediation": denial.remediation,
                }
            },
            "content": [{
                "type": "text",
                "text": text
            }],
            "isError": true
        }),
    )
}

fn apply_session_tool_limits(
    tool_name: &str,
    arguments: Value,
    session_policy: Option<&McpSessionPolicy>,
) -> Value {
    let Some(limit) = session_policy.and_then(|policy| policy.max_test_inference_cost_usd) else {
        return arguments;
    };
    if !matches!(tool_name, CHAT_TEST_TOOL | CHAT_COMPARE_TOOL) {
        return arguments;
    }

    let mut arguments = arguments;
    let Some(object) = arguments.as_object_mut() else {
        return arguments;
    };
    let requested_limit = object.get("max_cost_usd").and_then(Value::as_f64);
    if requested_limit.is_none_or(|value| value > limit) {
        object.insert("max_cost_usd".to_string(), serde_json::json!(limit));
    }
    arguments
}

fn filter_tool_servers_list_result(
    mut result: Value,
    session_policy: Option<&McpSessionPolicy>,
) -> Value {
    let Some(policy) = session_policy.and_then(|session| session.tool_servers.as_ref()) else {
        return result;
    };
    let Some(original_tool_servers) = result.get("tool_servers").and_then(Value::as_array) else {
        return result;
    };
    let filtered_tool_servers = original_tool_servers
        .iter()
        .filter(|tool_server| policy.allows_tool_server(tool_server))
        .cloned()
        .collect::<Vec<_>>();
    let approved_count = filtered_tool_servers
        .iter()
        .filter(|tool_server| {
            tool_server.get("trust_state").and_then(Value::as_str) == Some("approved")
        })
        .count();
    let pending_count = filtered_tool_servers.len().saturating_sub(approved_count);

    result["tool_servers"] = Value::Array(filtered_tool_servers.clone());

    if let Some(summary) = result.get_mut("summary").and_then(Value::as_object_mut) {
        summary.insert(
            "tool_server_count".to_string(),
            serde_json::json!(filtered_tool_servers.len()),
        );
        summary.insert(
            "approved_count".to_string(),
            serde_json::json!(approved_count),
        );
        summary.insert(
            "pending_count".to_string(),
            serde_json::json!(pending_count),
        );
    }

    result
}

fn enforce_tool_server_get_access(
    result: Value,
    session_policy: Option<&McpSessionPolicy>,
) -> Result<Value, ToolCallDenial> {
    let Some(policy) = session_policy.and_then(|session| session.tool_servers.as_ref()) else {
        return Ok(result);
    };
    let Some(tool_server) = result.get("tool_server") else {
        return Ok(result);
    };
    if result.get("ok").and_then(Value::as_bool) != Some(true) {
        return Ok(result);
    }
    if let Some(denial) = policy.denial_for_tool_server(tool_server) {
        return Err(denial);
    }
    Ok(result)
}

fn apply_tool_server_policy_to_result(
    tool_name: &str,
    result: Value,
    session_policy: Option<&McpSessionPolicy>,
) -> Result<Value, ToolCallDenial> {
    match tool_name {
        "tool_servers_list" => Ok(filter_tool_servers_list_result(result, session_policy)),
        "tool_server_get" => enforce_tool_server_get_access(result, session_policy),
        "tool_server_validate" => enforce_tool_server_validate_access(result, session_policy),
        _ => Ok(result),
    }
}

fn enforce_tool_server_validate_access(
    result: Value,
    session_policy: Option<&McpSessionPolicy>,
) -> Result<Value, ToolCallDenial> {
    let Some(policy) = session_policy.and_then(|session| session.tool_servers.as_ref()) else {
        return Ok(result);
    };
    if result.get("ok").and_then(Value::as_bool) != Some(true) {
        return Ok(result);
    }

    let Some(tool_servers) = result.get("tool_servers").and_then(Value::as_array) else {
        return Ok(result);
    };
    for tool_server in tool_servers {
        if let Some(denial) = policy.denial_for_tool_server(tool_server) {
            return Err(denial);
        }
    }

    Ok(result)
}

fn filter_gateway_tool_servers_resource_contents(
    mut result: Value,
    session_policy: Option<&McpSessionPolicy>,
) -> Result<Value, crate::error::CliError> {
    let Some(policy) = session_policy.and_then(|session| session.tool_servers.as_ref()) else {
        return Ok(result);
    };
    let Some(contents) = result.get_mut("contents").and_then(Value::as_array_mut) else {
        return Ok(result);
    };

    for content in contents {
        let Some(text) = content.get("text").and_then(Value::as_str) else {
            continue;
        };
        let mut payload: Value = serde_json::from_str(text).map_err(|error| {
            crate::error::CliError::internal(format!(
                "failed to decode gateway tool server resource payload: {error}"
            ))
        })?;
        if let Some(tool_servers) = payload
            .get_mut("tool_servers")
            .and_then(Value::as_array_mut)
        {
            tool_servers.retain(|tool_server| policy.allows_tool_server(tool_server));
        }
        content["text"] = Value::String(serde_json::to_string(&payload).map_err(|error| {
            crate::error::CliError::internal(format!(
                "failed to encode filtered gateway tool server resource payload: {error}"
            ))
        })?);
    }

    Ok(result)
}

pub(crate) async fn handle_jsonrpc_request_with_context(
    outbox: &mcp::audit::McpOutboxHandle,
    client: &AsyncApiClient,
    session_id: &str,
    request_id: Option<&str>,
    request: &Value,
    session_policy: Option<&McpSessionPolicy>,
    // The pre-effect sealed Trail-intent state machine (see `handle_tools_call`)
    // now owns both audit and trace capture, so the legacy detached
    // trace-context is no longer consumed here. The parameter is retained
    // because the transport layer (`transport::streamable_http`) and the
    // connected gateway still construct and thread `McpToolTraceContext`.
    _trace_context: Option<&McpToolTraceContext>,
) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");

    match method {
        "initialize" => handle_initialize(id),
        "initialized" => Value::Null,
        "tools/list" => handle_tools_list(id, session_policy),
        "tools/call" => {
            handle_tools_call(
                outbox,
                id,
                request,
                client,
                session_id,
                request_id,
                session_policy,
            )
            .await
        }
        "resources/list" => handle_resources_list(id, session_policy),
        "resources/read" => {
            handle_resources_read(id, request, client, session_id, session_policy).await
        }
        "ping" => jsonrpc_result(id, serde_json::json!({})),
        _ => jsonrpc_error(id, -32601, &format!("Method not found: {method}")),
    }
}

pub(crate) fn jsonrpc_result(id: Value, result: Value) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
}

pub(crate) fn jsonrpc_error(id: Value, code: i32, message: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        }
    })
}

fn handle_initialize(id: Value) -> Value {
    jsonrpc_result(
        id,
        serde_json::json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {
                "tools": { "listChanged": false },
                "resources": { "subscribe": false, "listChanged": false }
            },
            "serverInfo": {
                "name": MCP_SERVER_NAME,
                "version": MCP_SERVER_VERSION,
            }
        }),
    )
}

fn handle_tools_list(id: Value, session_policy: Option<&McpSessionPolicy>) -> Value {
    let mut tools = mcp::tools::tools_list();
    if let Some(policy) = session_policy {
        if let Some(values) = tools.as_array_mut() {
            values.retain(|tool| {
                tool.get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| policy.allows_tool(name))
            });
        }
    }
    jsonrpc_result(
        id,
        serde_json::json!({
            "tools": tools
        }),
    )
}

async fn handle_tools_call(
    outbox: &mcp::audit::McpOutboxHandle,
    id: Value,
    request: &Value,
    client: &AsyncApiClient,
    session_id: &str,
    request_id: Option<&str>,
    session_policy: Option<&McpSessionPolicy>,
) -> Value {
    let params = request.get("params").cloned().unwrap_or(Value::Null);
    let tool_name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or(Value::Object(serde_json::Map::new()));

    if let Some(policy) = session_policy {
        if !policy.allows_tool(tool_name) {
            return tool_call_denial_result(
                id,
                ToolCallDenial {
                    code: "mcp_tool_not_allowed",
                    message: format!("MCP tool '{}' is not allowed for this session", tool_name),
                    remediation: None,
                },
            );
        }
    }
    let arguments = apply_session_tool_limits(tool_name, arguments, session_policy);

    let bridge = session_policy
        .map(|policy| policy.action_bridge.clone())
        .unwrap_or_default();
    let session_meta = crate::gateway::runtimes::network::mcp::McpSessionMeta {
        session_id: Some(session_id.to_string()),
        authenticated_actor: Some(format!("mcp:session:{session_id}")),
        target_server: Some("mcp:published".to_string()),
        ..Default::default()
    };
    let governed_request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id.clone(),
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments.clone(),
        }
    });
    let decision = match crate::gateway::runtimes::network::mcp::govern_tool_call_before_dispatch(
        &bridge,
        &governed_request,
        Some(&session_meta),
    ) {
        Ok(Some(decision)) => decision,
        Ok(None) => {
            return tool_call_denial_result(
                id,
                ToolCallDenial {
                    code: "mcp_tool_governance_missing",
                    message: "MCP tool call missing pre-dispatch decision".to_string(),
                    remediation: None,
                },
            );
        }
        Err(error) => {
            return tool_call_denial_result(
                id,
                ToolCallDenial {
                    code: "mcp_tool_action_denied",
                    message: error.to_string(),
                    remediation: None,
                },
            );
        }
    };

    let _permit = match crate::gateway::runtimes::network::mcp::acquire_tool_concurrency_permit(
        &format!("published-mcp:{session_id}"),
        bridge.containment.max_concurrent_calls,
    ) {
        Ok(permit) => permit,
        Err(error) => {
            crate::gateway::runtimes::network::mcp::record_tool_action_failed();
            return tool_call_denial_result(
                id,
                ToolCallDenial {
                    code: "mcp_tool_concurrency_limit",
                    message: error.to_string(),
                    remediation: None,
                },
            );
        }
    };

    // SEC-020: recover every dispatched/indeterminate sealed effect (including
    // missing ciphertext) before accepting a new MCP call. Unresolved outcomes
    // fail closed so the prior effect cannot be re-dispatched.
    if let Err(error) = mcp::audit::ensure_recovered_before_serving(outbox, client).await {
        return recovery_blocked_result(id, tool_name, &error);
    }

    // Pre-effect sealed Trail-intent state machine.
    // Both audit and trace are routed through this single acknowledged path.
    // Fail closed: if the region cannot be resolved or the intent/recipient
    // cannot be obtained and durably recorded as `dispatched`, the external MCP
    // effect must not occur. No plaintext/redacted fallback path is added.
    let region_id = match mcp::audit::resolve_trail_intent_region_id(client).await {
        Ok(region_id) => region_id,
        Err(error) => return sealed_audit_unavailable_result(id, tool_name, &error),
    };
    let input_summary = mcp::audit::summarize_json(&arguments);
    let handle = match mcp::audit::prepare_sealed_tool_call(
        outbox,
        client,
        &region_id,
        session_id,
        request_id,
        session_id,
        tool_name,
        &input_summary,
    )
    .await
    {
        Ok(handle) => handle,
        Err(error) => return sealed_audit_unavailable_result(id, tool_name, &error),
    };

    let execution_idempotency_key = handle.execution_idempotency_key();
    let ctx = mcp::tools::ToolContext { client, session_id };

    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_millis(bridge.containment.timeout_ms.max(1));
    let executed = match tokio::time::timeout(
        timeout,
        mcp::tools::execute_tool_with_idempotency_key(
            &ctx,
            tool_name,
            &arguments,
            execution_idempotency_key,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(crate::error::CliError::user(format!(
            "mcp published tool call timed out after {}ms",
            timeout.as_millis()
        ))),
    };
    let duration_ms = start.elapsed().as_millis() as u64;

    match executed {
        Ok(result) => {
            let output_summary = mcp::audit::summarize_json(&result);
            let completion = mcp::audit::complete_sealed_tool_call(
                outbox,
                client,
                handle,
                &output_summary,
                true,
                duration_ms,
                None,
            )
            .await;
            if let Some(unresolved) = unresolved_effect_result(
                id.clone(),
                tool_name,
                execution_idempotency_key,
                completion,
            ) {
                crate::gateway::runtimes::network::mcp::record_tool_action_failed();
                return unresolved;
            }
            let result = match apply_tool_server_policy_to_result(tool_name, result, session_policy)
            {
                Ok(result) => result,
                Err(denial) => {
                    crate::gateway::runtimes::network::mcp::record_tool_action_failed();
                    return tool_call_denial_result(id, denial);
                }
            };

            crate::gateway::runtimes::network::mcp::record_tool_action_completed();
            let payload = serde_json::json!({
                "structuredContent": result,
                "content": [{
                    "type": "text",
                    "text": serde_json::to_string_pretty(&result).unwrap_or_default()
                }],
                "isError": false
            });
            crate::gateway::runtimes::network::mcp::bind_tool_action_result(
                jsonrpc_result(id, payload),
                &decision,
                "completed",
            )
        }
        Err(e) => {
            let error_code = "tool.execution_failed";
            let error_payload = serde_json::json!({
                "ok": false,
                "error": {
                    "code": error_code,
                    "message": e.to_string(),
                    "details": {
                        "tool_name": tool_name,
                    }
                }
            });
            let error_text = serde_json::to_string(&error_payload).unwrap_or_else(|_| {
                serde_json::json!({
                    "ok": false,
                    "error": {
                        "code": "tool.execution_failed",
                        "message": "internal serialization error",
                        "details": { "tool_name": tool_name }
                    }
                })
                .to_string()
            });
            let completion = mcp::audit::complete_sealed_tool_call(
                outbox,
                client,
                handle,
                &error_text,
                false,
                duration_ms,
                Some(error_code),
            )
            .await;
            if let Some(unresolved) = unresolved_effect_result(
                id.clone(),
                tool_name,
                execution_idempotency_key,
                completion,
            ) {
                crate::gateway::runtimes::network::mcp::record_tool_action_failed();
                return unresolved;
            }

            crate::gateway::runtimes::network::mcp::record_tool_action_failed();
            let payload = serde_json::json!({
                "structuredContent": error_payload,
                "content": [{
                    "type": "text",
                    "text": error_text
                }],
                "isError": true
            });
            crate::gateway::runtimes::network::mcp::bind_tool_action_result(
                jsonrpc_result(id, payload),
                &decision,
                "failed",
            )
        }
    }
}

/// Build the fail-closed JSON-RPC result returned when the sealed Trail-intent
/// authority is unavailable. The external MCP effect was NOT executed.
fn sealed_audit_unavailable_result(
    id: Value,
    tool_name: &str,
    error: &crate::error::CliError,
) -> Value {
    tracing::warn!(
        tool = %tool_name,
        error = %error,
        "sealed Trail-intent authority unavailable; MCP tool effect blocked (fail closed)"
    );
    let message = format!(
        "MCP tool '{tool_name}' was not executed: the sealed Trail audit authority is unavailable"
    );
    jsonrpc_result(
        id,
        serde_json::json!({
            "structuredContent": {
                "ok": false,
                "error": {
                    "code": "mcp.audit_unavailable",
                    "message": message,
                    "details": { "tool_name": tool_name }
                }
            },
            "content": [{
                "type": "text",
                "text": message
            }],
            "isError": true
        }),
    )
}

/// Fail closed when prior sealed effects remain unresolved after recovery.
/// The requested MCP effect was NOT executed.
fn recovery_blocked_result(id: Value, tool_name: &str, error: &crate::error::CliError) -> Value {
    tracing::warn!(
        tool = %tool_name,
        error = %error,
        "sealed MCP recovery blocked new tool dispatch; prior effect remains operator-visible"
    );
    let message = format!(
        "MCP tool '{tool_name}' was not executed: sealed effect recovery must complete before new calls"
    );
    jsonrpc_result(
        id,
        serde_json::json!({
            "structuredContent": {
                "ok": false,
                "error": {
                    "code": "mcp.effect_recovery_blocked",
                    "message": message,
                    "details": {
                        "tool_name": tool_name,
                        "operator_action": "inspect and recover the sealed MCP outbox before retrying",
                        "cause": error.to_string()
                    }
                }
            },
            "content": [{
                "type": "text",
                "text": message
            }],
            "isError": true
        }),
    )
}

/// Return an explicit unresolved-effect response whenever post-effect
/// durability or acknowledgement is not complete.
fn unresolved_effect_result(
    id: Value,
    tool_name: &str,
    execution_idempotency_key: uuid::Uuid,
    completion: Result<mcp::audit::SealedCompletion, crate::error::CliError>,
) -> Option<Value> {
    match completion {
        Ok(mcp::audit::SealedCompletion::Completed) => None,
        Ok(mcp::audit::SealedCompletion::Indeterminate) => {
            tracing::warn!(
                tool = %tool_name,
                execution_idempotency_key = %execution_idempotency_key,
                "sealed MCP audit acknowledgement is indeterminate; outbox record retained for recovery"
            );
            Some(effect_unresolved_response(
                id,
                tool_name,
                execution_idempotency_key,
                "acknowledgement is indeterminate",
            ))
        }
        Err(error) => {
            tracing::warn!(
                tool = %tool_name,
                execution_idempotency_key = %execution_idempotency_key,
                error = %error,
                "failed to complete sealed MCP audit; outbox record retained"
            );
            Some(effect_unresolved_response(
                id,
                tool_name,
                execution_idempotency_key,
                "post-effect audit persistence failed",
            ))
        }
    }
}

fn effect_unresolved_response(
    id: Value,
    tool_name: &str,
    execution_idempotency_key: uuid::Uuid,
    reason: &str,
) -> Value {
    let message =
        format!("MCP tool '{tool_name}' executed, but its durable outcome is unresolved: {reason}");
    jsonrpc_result(
        id,
        serde_json::json!({
            "structuredContent": {
                "ok": false,
                "error": {
                    "code": "mcp.effect_outcome_unresolved",
                    "message": message,
                    "details": {
                        "tool_name": tool_name,
                        "execution_idempotency_key": execution_idempotency_key.to_string(),
                        "operator_action": "inspect and recover the sealed MCP outbox before retrying"
                    }
                }
            },
            "content": [{
                "type": "text",
                "text": message
            }],
            "isError": true
        }),
    )
}

fn handle_resources_list(id: Value, session_policy: Option<&McpSessionPolicy>) -> Value {
    let mut resources = mcp::resources::resources_list();
    if let Some(policy) = session_policy {
        if let Some(values) = resources.as_array_mut() {
            values.retain(|resource| {
                resource
                    .get("uri")
                    .and_then(Value::as_str)
                    .is_some_and(|uri| policy.allows_resource(uri))
            });
        }
    }
    jsonrpc_result(
        id,
        serde_json::json!({
            "resources": resources
        }),
    )
}

async fn handle_resources_read(
    id: Value,
    request: &Value,
    client: &AsyncApiClient,
    session_id: &str,
    session_policy: Option<&McpSessionPolicy>,
) -> Value {
    let uri = request
        .get("params")
        .and_then(|p| p.get("uri"))
        .and_then(Value::as_str)
        .unwrap_or("");

    if let Some(policy) = session_policy {
        if !policy.allows_resource(uri) {
            return jsonrpc_error(
                id,
                -32602,
                &format!("MCP resource '{}' is not allowed for this session", uri),
            );
        }
    }

    match mcp::resources::read_resource_for_session(client, uri, Some(session_id)).await {
        Ok(result) => {
            let result = if is_gateway_tool_servers_resource_uri(uri) {
                match filter_gateway_tool_servers_resource_contents(result, session_policy) {
                    Ok(result) => result,
                    Err(error) => return jsonrpc_error(id, -32603, &error.to_string()),
                }
            } else {
                result
            };
            jsonrpc_result(id, result)
        }
        Err(e) => jsonrpc_error(id, -32602, &e.to_string()),
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

    use axum::{
        extract::{OriginalUri, Path, State},
        http::StatusCode,
        routing::{get, post},
        Json, Router,
    };
    use base64::Engine;
    use serde_json::{json, Value};
    use serial_test::serial;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };

    use super::*;

    const SEALED_REGION_UUID: &str = "11111111-1111-4111-8111-111111111111";
    const SEALED_INTENT_UUID: &str = "22222222-2222-4222-8222-222222222222";
    async fn sealed_create_intent(Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
        let append_identity = body
            .get("append_identity")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let recipient = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);
        let aad = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"sealed-aad");
        (
            StatusCode::CREATED,
            Json(json!({
                "intent_id": SEALED_INTENT_UUID,
                "region_registry_id": SEALED_REGION_UUID,
                "append_identity": append_identity,
                "event_kind": "mcp.tool_call",
                "recipient_generation": 1,
                "kem": "DHKEM(X25519,HKDF-SHA256)",
                "kdf": "HKDF-SHA256",
                "aead": "ChaCha20Poly1305",
                "recipient_public_key_base64url": recipient,
                "aad_base64url": aad,
                "expires_at": "2027-01-01T00:00:00Z",
            })),
        )
    }

    async fn sealed_acknowledge(
        State(state): State<MockApiState>,
        Path(intent_id): Path<String>,
        Json(body): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        if state.fail_ack.load(Ordering::SeqCst) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "injected acknowledgement failure"})),
            );
        }
        (
            StatusCode::OK,
            Json(json!({
                "intent_id": intent_id,
                "append_identity": body.get("append_identity").cloned().unwrap_or(Value::Null),
                "state": "acknowledged",
                "trail_event_id": "33333333-3333-4333-8333-333333333333",
                "payload_sha256": body.get("payload_sha256").cloned().unwrap_or(Value::Null),
            })),
        )
    }

    async fn sealed_regions() -> Json<Value> {
        Json(json!({ "regions": [{ "region_key": "eu-west", "id": SEALED_REGION_UUID }] }))
    }

    #[derive(Clone, Default)]
    struct MockApiState {
        request_paths: Arc<Mutex<Vec<String>>>,
        fail_ack: Arc<AtomicBool>,
    }

    impl MockApiState {
        fn record(&self, path: String) {
            self.request_paths
                .lock()
                .expect("request paths lock")
                .push(path);
        }

        fn request_paths(&self) -> Vec<String> {
            self.request_paths
                .lock()
                .expect("request paths lock")
                .clone()
        }

        fn fail_acknowledgements(&self) {
            self.fail_ack.store(true, Ordering::SeqCst);
        }
    }

    async fn history_search_handler(
        State(state): State<MockApiState>,
        uri: OriginalUri,
    ) -> Json<Value> {
        state.record(uri.0.to_string());
        Json(json!({
            "results": [{
                "session_id": "session-1",
                "session_title": "Escalation triage",
                "excerpt": "match excerpt",
                "entry_kind": "assistant",
                "captured_at": "2026-06-23T10:00:00Z"
            }]
        }))
    }

    async fn history_sessions_handler(
        State(state): State<MockApiState>,
        uri: OriginalUri,
    ) -> Json<Value> {
        state.record(uri.0.to_string());
        Json(json!({
            "sessions": [{
                "id": "session-1",
                "title": "Recent session"
            }]
        }))
    }

    async fn start_mock_api() -> (AsyncApiClient, MockApiState, tokio::task::JoinHandle<()>) {
        let state = MockApiState::default();
        let app = Router::new()
            .route("/v1/history/search", get(history_search_handler))
            .route("/v1/history/sessions", get(history_sessions_handler))
            .route("/v1/regions", get(sealed_regions))
            .route("/v1/trail/intents", post(sealed_create_intent))
            .route(
                "/v1/trail/intents/:intent_id/acknowledge",
                post(sealed_acknowledge),
            )
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock api");
        let addr = listener.local_addr().expect("mock api addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve mock api");
        });
        let client = AsyncApiClient::new(format!("http://{addr}"), "test-token")
            .expect("mock api client")
            .with_region(Some(SEALED_REGION_UUID.to_string()));
        (client, state, handle)
    }

    #[tokio::test]
    async fn handle_jsonrpc_request_returns_initialize_payload() {
        let client = AsyncApiClient::new("http://127.0.0.1:9", "test-token").expect("client");
        let outbox = mcp::audit::McpOutboxHandle::from_env();
        let response = handle_jsonrpc_request_with_context(
            &outbox,
            &client,
            "session-1",
            None,
            &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
            None,
            None,
        )
        .await;

        assert_eq!(response["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);
        assert_eq!(response["result"]["serverInfo"]["name"], MCP_SERVER_NAME);
    }

    #[tokio::test]
    async fn handle_jsonrpc_request_reads_history_sessions_resource() {
        let (client, state, handle) = start_mock_api().await;
        let outbox = mcp::audit::McpOutboxHandle::from_env();

        let response = handle_jsonrpc_request_with_context(
            &outbox,
            &client,
            "session-1",
            None,
            &json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "resources/read",
                "params": {
                    "uri": "history://sessions"
                }
            }),
            None,
            None,
        )
        .await;

        assert_eq!(
            response["result"]["contents"][0]["text"],
            "[{\"id\":\"session-1\",\"title\":\"Recent session\"}]"
        );
        assert!(state
            .request_paths()
            .contains(&"/v1/history/sessions?limit=50".to_string()));

        handle.abort();
    }

    #[test]
    fn jsonrpc_error_wraps_code_and_message() {
        let response = jsonrpc_error(json!(7), -32601, "missing");

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 7);
        assert_eq!(response["error"]["code"], -32601);
        assert_eq!(response["error"]["message"], "missing");
    }

    #[test]
    fn tools_list_respects_session_policy() {
        let response = handle_tools_list(
            json!(1),
            Some(&McpSessionPolicy {
                allowed_tools: MatchListOrWildcard::Explicit(vec!["other_tool".to_string()]),
                ..McpSessionPolicy::default()
            }),
        );

        assert_eq!(response["result"]["tools"], json!([]));
    }

    #[tokio::test]
    async fn tools_call_rejects_disallowed_tool() {
        let client = AsyncApiClient::new("http://127.0.0.1:9", "test-token").expect("client");
        let outbox = mcp::audit::McpOutboxHandle::from_env();
        let response = handle_jsonrpc_request_with_context(
            &outbox,
            &client,
            "session-1",
            None,
            &json!({
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {
                    "name": "history_search",
                    "arguments": {
                        "query": "blocked"
                    }
                }
            }),
            Some(&McpSessionPolicy {
                allowed_tools: MatchListOrWildcard::Explicit(vec!["models_list".to_string()]),
                ..McpSessionPolicy::default()
            }),
            None,
        )
        .await;

        assert_eq!(response["result"]["isError"], true);
        assert!(response["result"]["content"][0]["text"]
            .as_str()
            .expect("text")
            .contains("not allowed"));
    }

    #[test]
    fn resources_list_respects_session_policy() {
        let response = handle_resources_list(
            json!(1),
            Some(&McpSessionPolicy {
                allowed_resources: MatchListOrWildcard::Explicit(vec![
                    "history://other".to_string()
                ]),
                ..McpSessionPolicy::default()
            }),
        );

        assert_eq!(response["result"]["resources"], json!([]));
    }

    #[test]
    fn resources_allowlists_match_templates_wildcards_and_legacy_aliases() {
        let policy = McpSessionPolicy {
            allowed_resources: MatchListOrWildcard::Explicit(vec![
                "history://session/{id}".to_string(),
                "context://branch/*".to_string(),
                "gateway-tool-servers://declared".to_string(),
            ]),
            ..McpSessionPolicy::default()
        };

        assert!(policy.allows_resource("history://session/sess%2F1?include_entries=true"));
        assert!(policy.allows_resource("history://session/{id}"));
        assert!(policy.allows_resource("context://branch/{name}"));
        assert!(policy.allows_resource("context://branch/main?limit=10"));
        assert!(policy.allows_resource("gateway://tool-servers"));
        assert!(policy.allows_resource("gateway://tool-servers?path=/tmp/policy.yaml"));
        assert!(!policy.allows_resource("regions://catalog"));
    }

    #[test]
    fn resources_list_keeps_canonical_uris_when_legacy_aliases_are_allowlisted() {
        let response = handle_resources_list(
            json!(11),
            Some(&McpSessionPolicy {
                allowed_resources: MatchListOrWildcard::Explicit(vec![
                    "gateway-tool-servers://declared".to_string(),
                    "history://session/{id}".to_string(),
                ]),
                ..McpSessionPolicy::default()
            }),
        );

        let resource_uris: Vec<&str> = response["result"]["resources"]
            .as_array()
            .expect("resources array")
            .iter()
            .filter_map(|resource| resource.get("uri").and_then(Value::as_str))
            .collect();

        assert_eq!(
            resource_uris,
            vec!["history://session/{id}", "gateway://tool-servers"]
        );
    }

    #[tokio::test]
    async fn resources_read_rejects_disallowed_resource() {
        let client = AsyncApiClient::new("http://127.0.0.1:9", "test-token").expect("client");
        let outbox = mcp::audit::McpOutboxHandle::from_env();
        let response = handle_jsonrpc_request_with_context(
            &outbox,
            &client,
            "session-1",
            None,
            &json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "resources/read",
                "params": {
                    "uri": "history://sessions"
                }
            }),
            Some(&McpSessionPolicy {
                allowed_resources: MatchListOrWildcard::Explicit(vec![
                    "history://other".to_string()
                ]),
                ..McpSessionPolicy::default()
            }),
            None,
        )
        .await;

        assert_eq!(response["error"]["code"], -32602);
        assert!(response["error"]["message"]
            .as_str()
            .expect("message")
            .contains("not allowed"));
    }

    #[test]
    fn apply_session_tool_limits_caps_chat_test_max_cost() {
        let constrained = apply_session_tool_limits(
            CHAT_TEST_TOOL,
            json!({
                "model": "gpt-5.4-mini",
                "max_cost_usd": 5.0
            }),
            Some(&McpSessionPolicy {
                max_test_inference_cost_usd: Some(1.25),
                ..McpSessionPolicy::default()
            }),
        );

        assert_eq!(constrained["max_cost_usd"], json!(1.25));
    }

    #[test]
    fn tool_servers_list_filters_unapproved_and_disallowed_ids() {
        let filtered = filter_tool_servers_list_result(
            json!({
                "ok": true,
                "summary": {
                    "tool_server_count": 2,
                    "approved_count": 1,
                    "pending_count": 1
                },
                "tool_servers": [
                    {
                        "id": "approved-db-tool",
                        "trust_state": "approved"
                    },
                    {
                        "id": "pending-browser",
                        "trust_state": "pending"
                    }
                ]
            }),
            Some(&McpSessionPolicy {
                tool_servers: Some(McpToolServerPolicy {
                    allow_unapproved: false,
                    allowed_ids: vec!["approved-db-tool".to_string()],
                }),
                ..McpSessionPolicy::default()
            }),
        );

        assert_eq!(filtered["summary"]["tool_server_count"], 1);
        assert_eq!(filtered["summary"]["approved_count"], 1);
        assert_eq!(filtered["summary"]["pending_count"], 0);
        assert_eq!(
            filtered["tool_servers"],
            json!([{
                "id": "approved-db-tool",
                "trust_state": "approved"
            }])
        );
    }

    #[test]
    fn tool_server_get_rejects_unapproved_servers() {
        let denial = enforce_tool_server_get_access(
            json!({
                "ok": true,
                "tool_server": {
                    "id": "pending-browser",
                    "trust_state": "pending"
                }
            }),
            Some(&McpSessionPolicy {
                tool_servers: Some(McpToolServerPolicy {
                    allow_unapproved: false,
                    allowed_ids: Vec::new(),
                }),
                ..McpSessionPolicy::default()
            }),
        )
        .expect_err("pending server should be denied");

        assert_eq!(denial.code, TOOL_SERVER_ACCESS_DENIED_CODE);
        assert!(denial.message.contains("not approved"));
    }

    #[test]
    fn tool_server_validate_rejects_disallowed_servers() {
        let denial = enforce_tool_server_validate_access(
            json!({
                "ok": true,
                "tool_servers": [{
                    "id": "pending-browser",
                    "trust_state": "pending"
                }]
            }),
            Some(&McpSessionPolicy {
                tool_servers: Some(McpToolServerPolicy {
                    allow_unapproved: false,
                    allowed_ids: vec!["approved-db-tool".to_string()],
                }),
                ..McpSessionPolicy::default()
            }),
        )
        .expect_err("pending server should be denied");

        assert_eq!(denial.code, TOOL_SERVER_ACCESS_DENIED_CODE);
        assert!(
            denial.message.contains("not permitted") || denial.message.contains("not approved")
        );
    }

    #[test]
    fn gateway_tool_servers_resource_contents_are_filtered() {
        let filtered = filter_gateway_tool_servers_resource_contents(
            json!({
                "contents": [{
                    "uri": "gateway://tool-servers",
                    "mimeType": "application/json",
                    "text": serde_json::to_string(&json!({
                        "tool_servers": [
                            {
                                "id": "approved-db-tool",
                                "trust_state": "approved"
                            },
                            {
                                "id": "pending-browser",
                                "trust_state": "pending"
                            }
                        ]
                    }))
                    .expect("json text")
                }]
            }),
            Some(&McpSessionPolicy {
                tool_servers: Some(McpToolServerPolicy {
                    allow_unapproved: false,
                    allowed_ids: vec!["approved-db-tool".to_string()],
                }),
                ..McpSessionPolicy::default()
            }),
        )
        .expect("filtered resource");

        let payload: Value = serde_json::from_str(
            filtered["contents"][0]["text"]
                .as_str()
                .expect("filtered resource text"),
        )
        .expect("filtered payload");
        assert_eq!(
            payload["tool_servers"],
            json!([{
                "id": "approved-db-tool",
                "trust_state": "approved"
            }])
        );
    }
}
