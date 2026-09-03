// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

#![allow(clippy::items_after_test_module)]

use std::collections::HashMap;
use std::time::Duration;

use serde_json::Value;

use crate::secret_key_ref::deserialize_optional_env_secret_key_name;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Default)]
pub struct SemanticValidationConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(
        default,
        skip_serializing,
        rename = "secret_key_ref",
        deserialize_with = "deserialize_optional_env_secret_key_name"
    )]
    pub secret_key_env: Option<String>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Default)]
pub struct ToolValidationConfig {
    #[serde(default)]
    pub declared_tools: Vec<String>,
    #[serde(default)]
    pub schemas: HashMap<String, Value>,
    #[serde(default)]
    pub allow_undeclared: bool,
    #[serde(default)]
    pub semantic_validation: SemanticValidationConfig,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ToolValidationDecision {
    pub requested_tools: Vec<String>,
    pub undeclared_tools: Vec<String>,
    pub invalid_schemas: Vec<String>,
    pub valid: bool,
    pub semantic_validated: bool,
    pub semantic_reason: Option<String>,
}

/// Actual tool invocation evaluated immediately before dispatch.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ToolActionContext {
    pub tool_name: String,
    pub arguments: Value,
    pub authenticated_actor: String,
    pub target_server: String,
    pub remaining_action_budget: u64,
}

/// Combined allow/deny decision recorded into durable evidence without secrets.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ToolActionPreDispatchDecision {
    pub allowed: bool,
    pub reason: Option<String>,
    pub argument_digest: String,
    pub tool_name: String,
    pub authenticated_actor: String,
    pub target_server: String,
    pub remaining_action_budget: u64,
    pub validation: ToolValidationDecision,
    pub security: crate::gateway::tool_security::ToolSecurityDecision,
    pub budget: crate::gateway::tool_budget::ToolBudgetDecision,
    pub evidence: Value,
}

const SECRET_KEY_FRAGMENTS: &[&str] = &[
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "access_key",
    "private_key",
    "secret_key",
];

fn key_looks_secret(key: &str) -> bool {
    let normalized = key.trim().to_ascii_lowercase().replace('-', "_");
    SECRET_KEY_FRAGMENTS
        .iter()
        .any(|fragment| normalized.contains(fragment))
}

fn string_looks_secret(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.starts_with("Bearer ")
        || trimmed.starts_with("bearer ")
        || trimmed.starts_with("sk-")
        || trimmed.starts_with("sk_live_")
        || trimmed.starts_with("sk_test_")
        || trimmed.starts_with("ghp_")
        || trimmed.starts_with("gho_")
        || trimmed.starts_with("glpat-")
        || trimmed.starts_with("xoxb-")
        || trimmed.starts_with("xoxp-")
        || trimmed.starts_with("AKIA")
}

/// Canonicalize JSON arguments for digesting: sorted object keys, secret-safe.
pub fn canonicalize_arguments_for_digest(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut ordered = serde_json::Map::new();
            let mut keys = map.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            for key in keys {
                let child = map.get(&key).cloned().unwrap_or(Value::Null);
                if key_looks_secret(&key) {
                    ordered.insert(key, Value::String("[REDACTED]".to_string()));
                } else {
                    ordered.insert(key, canonicalize_arguments_for_digest(&child));
                }
            }
            Value::Object(ordered)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(canonicalize_arguments_for_digest)
                .collect(),
        ),
        Value::String(text) if string_looks_secret(text) => Value::String("[REDACTED]".to_string()),
        other => other.clone(),
    }
}

/// Exact canonical argument digest for evidence (`sha256:...`), never raw secrets.
pub fn canonical_argument_digest(arguments: &Value) -> String {
    let canonical = canonicalize_arguments_for_digest(arguments);
    let bytes = serde_json::to_vec(&canonical).unwrap_or_else(|_| b"null".to_vec());
    crate::gateway::declarative_config::sha256_prefixed(&bytes)
}

fn default_timeout_ms() -> u64 {
    3_000
}

pub fn extract_requested_tools(request_json: Option<&Value>) -> Vec<String> {
    let Some(request_json) = request_json else {
        return Vec::new();
    };
    request_json
        .get("tools")
        .and_then(|value| value.as_array())
        .map(|tools| {
            tools
                .iter()
                .filter_map(|tool| {
                    tool.get("function")
                        .and_then(|value| value.get("name"))
                        .and_then(|value| value.as_str())
                        .or_else(|| tool.get("name").and_then(|value| value.as_str()))
                        .map(ToString::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
}

pub async fn validate_tools(
    config: &ToolValidationConfig,
    request_json: Option<&Value>,
) -> ToolValidationDecision {
    let requested_tools = extract_requested_tools(request_json);
    let undeclared_tools = requested_tools
        .iter()
        .filter(|name| !config.declared_tools.is_empty() && !config.declared_tools.contains(name))
        .cloned()
        .collect::<Vec<_>>();

    let invalid_schemas = config
        .schemas
        .iter()
        .filter_map(|(name, schema)| {
            jsonschema::JSONSchema::options()
                .with_draft(jsonschema::Draft::Draft7)
                .compile(schema)
                .map(|_| None)
                .unwrap_or_else(|_| Some(name.clone()))
        })
        .collect::<Vec<_>>();

    let mut valid =
        invalid_schemas.is_empty() && (config.allow_undeclared || undeclared_tools.is_empty());
    let mut semantic_reason = None;
    let mut semantic_validated = false;

    if valid && config.semantic_validation.enabled {
        semantic_validated = true;
        if let Some(error) = validate_tools_semantically(config, request_json)
            .await
            .err()
        {
            valid = false;
            semantic_reason = Some(error);
        }
    }

    ToolValidationDecision {
        requested_tools,
        undeclared_tools,
        invalid_schemas,
        valid,
        semantic_validated,
        semantic_reason,
    }
}

/// Validate one actual tool name + JSON arguments before dispatch.
pub async fn validate_tool_action(
    config: &ToolValidationConfig,
    ctx: &ToolActionContext,
) -> ToolValidationDecision {
    let tool_name = ctx.tool_name.trim();
    let requested_tools = if tool_name.is_empty() {
        Vec::new()
    } else {
        vec![tool_name.to_string()]
    };

    let undeclared_tools = requested_tools
        .iter()
        .filter(|name| !config.declared_tools.is_empty() && !config.declared_tools.contains(name))
        .cloned()
        .collect::<Vec<_>>();

    let mut invalid_schemas = Vec::new();
    if let Some(schema) = config.schemas.get(tool_name) {
        match jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft7)
            .compile(schema)
        {
            Ok(compiled) => {
                if compiled.validate(&ctx.arguments).is_err() {
                    invalid_schemas.push(tool_name.to_string());
                }
            }
            Err(_) => invalid_schemas.push(tool_name.to_string()),
        }
    }

    let mut valid =
        invalid_schemas.is_empty() && (config.allow_undeclared || undeclared_tools.is_empty());
    if tool_name.is_empty() {
        valid = false;
    }

    let mut semantic_reason = None;
    let mut semantic_validated = false;
    if valid && config.semantic_validation.enabled {
        semantic_validated = true;
        let synthetic = serde_json::json!({
            "tools": [{ "name": tool_name }],
            "arguments": ctx.arguments,
        });
        if let Some(error) = validate_tools_semantically(config, Some(&synthetic))
            .await
            .err()
        {
            valid = false;
            semantic_reason = Some(error);
        }
    }

    ToolValidationDecision {
        requested_tools,
        undeclared_tools,
        invalid_schemas,
        valid,
        semantic_validated,
        semantic_reason,
    }
}

/// Evaluate validation, security, and action budget immediately before dispatch.
///
/// Evidence carries the exact [`canonical_argument_digest`] and never persists
/// configured secret argument values.
pub async fn evaluate_tool_action_before_dispatch(
    validation_config: &ToolValidationConfig,
    security_config: &crate::gateway::tool_security::ToolSecurityConfig,
    budget_config: &crate::gateway::tool_budget::ToolBudgetConfig,
    ctx: &ToolActionContext,
) -> ToolActionPreDispatchDecision {
    let argument_digest = canonical_argument_digest(&ctx.arguments);
    let validation = validate_tool_action(validation_config, ctx).await;
    let security = crate::gateway::tool_security::analyze_tool_action(
        security_config,
        &ctx.tool_name,
        &ctx.arguments,
        &ctx.authenticated_actor,
        &ctx.target_server,
    )
    .await;
    let budget = crate::gateway::tool_budget::evaluate_action_budget(
        budget_config,
        &ctx.tool_name,
        ctx.remaining_action_budget,
    );

    let mut reason = None;
    if !validation.valid {
        reason = Some(
            validation
                .semantic_reason
                .clone()
                .or_else(|| {
                    if !validation.undeclared_tools.is_empty() {
                        Some(format!(
                            "undeclared_tools:{}",
                            validation.undeclared_tools.join(",")
                        ))
                    } else if !validation.invalid_schemas.is_empty() {
                        Some(format!(
                            "invalid_arguments:{}",
                            validation.invalid_schemas.join(",")
                        ))
                    } else if ctx.tool_name.trim().is_empty() {
                        Some("missing_tool_name".to_string())
                    } else {
                        Some("tool_validation_failed".to_string())
                    }
                })
                .unwrap_or_else(|| "tool_validation_failed".to_string()),
        );
    } else if security.flagged {
        reason = Some(
            security
                .reason
                .clone()
                .unwrap_or_else(|| "tool_security_flagged".to_string()),
        );
    } else if budget.flagged {
        reason = Some(format!(
            "action_budget_exhausted:{}",
            budget.exceeded_tools.join(",")
        ));
    }

    let allowed = reason.is_none();
    let evidence = serde_json::json!({
        "stage": "tool_action_pre_dispatch",
        "tool_name": ctx.tool_name,
        "argument_digest": argument_digest,
        "authenticated_actor": ctx.authenticated_actor,
        "target_server": ctx.target_server,
        "remaining_action_budget": ctx.remaining_action_budget,
        "decision": if allowed { "allow" } else { "deny" },
        "reason": reason,
        "validation": {
            "valid": validation.valid,
            "requested_tools": validation.requested_tools,
            "undeclared_tools": validation.undeclared_tools,
            "invalid_schemas": validation.invalid_schemas,
            "semantic_validated": validation.semantic_validated,
            "semantic_reason": validation.semantic_reason,
        },
        "security": {
            "flagged": security.flagged,
            "reason": security.reason,
            "matched_entities": security.matched_entities,
            "provider_verdict": security.provider_verdict,
        },
        "budget": {
            "flagged": budget.flagged,
            "exceeded_tools": budget.exceeded_tools,
        },
    });

    ToolActionPreDispatchDecision {
        allowed,
        reason,
        argument_digest,
        tool_name: ctx.tool_name.clone(),
        authenticated_actor: ctx.authenticated_actor.clone(),
        target_server: ctx.target_server.clone(),
        remaining_action_budget: ctx.remaining_action_budget,
        validation,
        security,
        budget,
        evidence,
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
    use serde_json::json;

    fn action_ctx(tool_name: &str, arguments: Value) -> ToolActionContext {
        ToolActionContext {
            tool_name: tool_name.to_string(),
            arguments,
            authenticated_actor: "actor:user-1".to_string(),
            target_server: "tool-server:docs".to_string(),
            remaining_action_budget: 2,
        }
    }

    #[test]
    fn extract_requested_tools_none_input() {
        assert_eq!(extract_requested_tools(None), Vec::<String>::new());
    }

    #[test]
    fn extract_requested_tools_no_tools_field() {
        let body = json!({"messages": []});
        assert_eq!(extract_requested_tools(Some(&body)), Vec::<String>::new());
    }

    #[test]
    fn extract_requested_tools_empty_array() {
        let body = json!({"tools": []});
        assert_eq!(extract_requested_tools(Some(&body)), Vec::<String>::new());
    }

    #[test]
    fn extract_requested_tools_function_name_format() {
        let body = json!({
            "tools": [
                {"function": {"name": "search"}},
                {"function": {"name": "write_file"}}
            ]
        });
        assert_eq!(
            extract_requested_tools(Some(&body)),
            vec!["search".to_string(), "write_file".to_string()]
        );
    }

    #[test]
    fn extract_requested_tools_direct_name_format() {
        let body = json!({
            "tools": [
                {"name": "tool_a"},
                {"name": "tool_b"}
            ]
        });
        assert_eq!(
            extract_requested_tools(Some(&body)),
            vec!["tool_a".to_string(), "tool_b".to_string()]
        );
    }

    #[test]
    fn extract_requested_tools_mixed_formats() {
        let body = json!({
            "tools": [
                {"function": {"name": "fn_tool"}},
                {"name": "direct_tool"},
                {"description": "no name"}
            ]
        });
        let result = extract_requested_tools(Some(&body));
        assert_eq!(
            result,
            vec!["fn_tool".to_string(), "direct_tool".to_string()]
        );
    }

    #[test]
    fn extract_requested_tools_function_name_takes_priority() {
        let body = json!({
            "tools": [
                {"function": {"name": "priority"}, "name": "fallback"}
            ]
        });
        assert_eq!(
            extract_requested_tools(Some(&body)),
            vec!["priority".to_string()]
        );
    }

    #[tokio::test]
    async fn validate_tools_empty_config_allows_all() {
        let config = ToolValidationConfig::default();
        let body = json!({
            "tools": [{"function": {"name": "any_tool"}}]
        });
        let result = validate_tools(&config, Some(&body)).await;
        assert!(result.valid);
        assert!(result.undeclared_tools.is_empty());
        assert!(result.invalid_schemas.is_empty());
        assert!(!result.semantic_validated);
    }

    #[tokio::test]
    async fn validate_tools_undeclared_blocked_when_not_allowed() {
        let config = ToolValidationConfig {
            declared_tools: vec!["search".to_string()],
            allow_undeclared: false,
            ..Default::default()
        };
        let body = json!({
            "tools": [
                {"function": {"name": "search"}},
                {"function": {"name": "unknown_tool"}}
            ]
        });
        let result = validate_tools(&config, Some(&body)).await;
        assert!(!result.valid);
        assert_eq!(result.undeclared_tools, vec!["unknown_tool".to_string()]);
    }

    #[tokio::test]
    async fn validate_tools_undeclared_allowed_when_configured() {
        let config = ToolValidationConfig {
            declared_tools: vec!["search".to_string()],
            allow_undeclared: true,
            ..Default::default()
        };
        let body = json!({
            "tools": [{"function": {"name": "unknown_tool"}}]
        });
        let result = validate_tools(&config, Some(&body)).await;
        assert!(result.valid);
        assert_eq!(result.undeclared_tools, vec!["unknown_tool".to_string()]);
    }

    #[tokio::test]
    async fn validate_tools_invalid_schema_detected() {
        let mut schemas = std::collections::HashMap::new();
        schemas.insert(
            "bad_schema".to_string(),
            json!({"type": "invalid_type_value"}),
        );
        let config = ToolValidationConfig {
            schemas,
            allow_undeclared: true,
            ..Default::default()
        };
        let result = validate_tools(&config, None).await;
        assert!(!result.valid);
        assert!(result.invalid_schemas.contains(&"bad_schema".to_string()));
    }

    #[tokio::test]
    async fn validate_tools_valid_schema_passes() {
        let mut schemas = std::collections::HashMap::new();
        schemas.insert(
            "good_schema".to_string(),
            json!({
                "type": "object",
                "properties": {"name": {"type": "string"}}
            }),
        );
        let config = ToolValidationConfig {
            schemas,
            allow_undeclared: true,
            ..Default::default()
        };
        let result = validate_tools(&config, None).await;
        assert!(result.valid);
        assert!(result.invalid_schemas.is_empty());
    }

    #[tokio::test]
    async fn validate_tools_no_request_json() {
        let config = ToolValidationConfig::default();
        let result = validate_tools(&config, None).await;
        assert!(result.valid);
        assert!(result.requested_tools.is_empty());
    }

    #[test]
    fn default_timeout_ms_value() {
        assert_eq!(default_timeout_ms(), 3_000);
    }

    #[test]
    fn semantic_validation_config_defaults() {
        let config = SemanticValidationConfig::default();
        assert!(!config.enabled);
        assert!(config.endpoint.is_none());
        assert!(config.model.is_none());
        // Default::default gives u64 default (0); serde default fn only applies during deserialization
        assert_eq!(config.timeout_ms, 0);
    }

    #[test]
    fn canonical_argument_digest_is_order_independent_and_secret_safe() {
        let a = json!({"b": 1, "a": 2, "api_key": "sk-live-secret"});
        let b = json!({"api_key": "sk-live-secret", "a": 2, "b": 1});
        let digest_a = canonical_argument_digest(&a);
        let digest_b = canonical_argument_digest(&b);
        assert_eq!(digest_a, digest_b);
        assert!(digest_a.starts_with("sha256:"));
        let canonical = canonicalize_arguments_for_digest(&a).to_string();
        assert!(!canonical.contains("sk-live-secret"));
        assert!(canonical.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn validate_tool_action_checks_actual_arguments_against_schema() {
        let mut schemas = std::collections::HashMap::new();
        schemas.insert(
            "search".to_string(),
            json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["q"],
                "properties": {"q": {"type": "string"}}
            }),
        );
        let config = ToolValidationConfig {
            declared_tools: vec!["search".to_string()],
            schemas,
            allow_undeclared: false,
            ..Default::default()
        };
        let ok = validate_tool_action(&config, &action_ctx("search", json!({"q": "rust"}))).await;
        assert!(ok.valid);
        let bad = validate_tool_action(&config, &action_ctx("search", json!({"q": 12}))).await;
        assert!(!bad.valid);
        assert_eq!(bad.invalid_schemas, vec!["search".to_string()]);
    }

    #[tokio::test]
    async fn evaluate_before_dispatch_blocks_undeclared_actual_tool_name() {
        let config = ToolValidationConfig {
            declared_tools: vec!["search".to_string()],
            allow_undeclared: false,
            ..Default::default()
        };
        let decision = evaluate_tool_action_before_dispatch(
            &config,
            &crate::gateway::tool_security::ToolSecurityConfig::default(),
            &crate::gateway::tool_budget::ToolBudgetConfig::default(),
            &action_ctx("delete_file", json!({"path": "/tmp/x"})),
        )
        .await;
        assert!(!decision.allowed);
        assert!(decision
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("undeclared_tools"));
        assert!(decision.evidence.get("arguments").is_none());
    }

    #[tokio::test]
    async fn evaluate_before_dispatch_records_digest_without_secret_bypass() {
        let config = ToolValidationConfig {
            declared_tools: vec!["upload".to_string()],
            ..Default::default()
        };
        let args = json!({
            "path": "/tmp/demo",
            "token": "super-secret-token-value",
            "nested": {"password": "hunter2"}
        });
        let decision = evaluate_tool_action_before_dispatch(
            &config,
            &crate::gateway::tool_security::ToolSecurityConfig::default(),
            &crate::gateway::tool_budget::ToolBudgetConfig::default(),
            &action_ctx("upload", args),
        )
        .await;
        assert!(decision.allowed);
        let rendered = decision.evidence.to_string();
        assert!(!rendered.contains("super-secret-token-value"));
        assert!(!rendered.contains("hunter2"));
        assert_eq!(
            decision.evidence["argument_digest"],
            decision.argument_digest
        );
    }

    #[tokio::test]
    async fn evaluate_before_dispatch_surfaces_security_flag_reason() {
        let config = ToolValidationConfig {
            declared_tools: vec!["shell".to_string()],
            ..Default::default()
        };
        let decision = evaluate_tool_action_before_dispatch(
            &config,
            &crate::gateway::tool_security::ToolSecurityConfig::default(),
            &crate::gateway::tool_budget::ToolBudgetConfig::default(),
            &action_ctx("shell", json!({"cmd": "rm -rf /"})),
        )
        .await;
        assert!(!decision.allowed);
        assert!(decision
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("matched_pattern:rm -rf"));
    }
}

async fn validate_tools_semantically(
    config: &ToolValidationConfig,
    request_json: Option<&Value>,
) -> Result<(), String> {
    let endpoint = config
        .semantic_validation
        .endpoint
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "semantic validation requires endpoint".to_string())?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(
            config.semantic_validation.timeout_ms.max(1),
        ))
        .build()
        .map_err(|error| format!("semantic validation client build failed: {error}"))?;

    let tools = request_json
        .and_then(|value| value.get("tools"))
        .cloned()
        .unwrap_or(Value::Array(Vec::new()));
    let request_payload = serde_json::json!({
        "model": config.semantic_validation.model.clone().unwrap_or_else(|| "judge".to_string()),
        "messages": [{
            "role": "user",
            "content": serde_json::json!({
                "declared_tools": config.declared_tools,
                "schemas": config.schemas,
                "request_tools": tools,
            }).to_string(),
        }],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "tool_semantic_validation",
                "schema": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["valid"],
                    "properties": {
                        "valid": {"type": "boolean"},
                        "reason": {"type": "string"}
                    }
                }
            }
        }
    });

    let mut request = client.post(endpoint).json(&request_payload);
    if let Some(secret_key_env) = &config.semantic_validation.secret_key_env {
        if let Ok(api_key) = std::env::var(secret_key_env) {
            if !api_key.trim().is_empty() {
                request = request.bearer_auth(api_key.trim());
            }
        }
    }

    let response = request
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|error| format!("semantic validation request failed: {error}"))?;
    let payload: Value = response
        .json()
        .await
        .map_err(|error| format!("semantic validation returned invalid JSON: {error}"))?;

    let result = payload
        .get("valid")
        .and_then(Value::as_bool)
        .map(|valid| {
            (
                valid,
                payload
                    .get("reason")
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
            )
        })
        .or_else(|| {
            payload
                .pointer("/choices/0/message/content")
                .and_then(Value::as_str)
                .and_then(|content| serde_json::from_str::<Value>(content).ok())
                .and_then(|content| {
                    content.get("valid").and_then(Value::as_bool).map(|valid| {
                        (
                            valid,
                            content
                                .get("reason")
                                .and_then(Value::as_str)
                                .map(ToString::to_string),
                        )
                    })
                })
        })
        .ok_or_else(|| "semantic validation response missing valid flag".to_string())?;

    if result.0 {
        Ok(())
    } else {
        Err(result
            .1
            .unwrap_or_else(|| "semantic tool validation failed".to_string()))
    }
}
