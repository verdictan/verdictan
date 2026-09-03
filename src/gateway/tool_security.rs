// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use serde_json::Value;

use crate::gateway::detection::entities::{blocked_findings, detect_entities};
use crate::secret_key_ref::deserialize_optional_env_secret_key_name;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AnalysisMode {
    #[default]
    Local,
    External,
}

fn default_fail_closed() -> bool {
    true
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ToolSecurityConfig {
    #[serde(default)]
    pub analysis_mode: AnalysisMode,
    #[serde(default)]
    pub firewall_endpoint: Option<String>,
    #[serde(
        default,
        rename = "secret_key_ref",
        skip_serializing,
        deserialize_with = "deserialize_optional_env_secret_key_name"
    )]
    pub secret_key_env: Option<String>,
    #[serde(default = "default_fail_closed")]
    pub fail_closed: bool,
    #[serde(default)]
    pub blocked_entity_types: Vec<String>,
    #[serde(default)]
    pub blocked_patterns: Vec<String>,
}

impl Default for ToolSecurityConfig {
    fn default() -> Self {
        Self {
            analysis_mode: AnalysisMode::Local,
            firewall_endpoint: None,
            secret_key_env: None,
            fail_closed: default_fail_closed(),
            blocked_entity_types: Vec::new(),
            blocked_patterns: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ToolSecurityDecision {
    pub flagged: bool,
    pub reason: Option<String>,
    pub matched_entities: Vec<String>,
    pub provider_verdict: Option<String>,
}

const LOCAL_PATTERNS: &[&str] = &[
    "../",
    "..\\",
    "drop table",
    "rm -rf",
    "169.254.169.254",
    "file://",
    "curl http://localhost",
];

pub async fn analyze_request(
    config: &ToolSecurityConfig,
    request_json: Option<&Value>,
) -> ToolSecurityDecision {
    let request_text_raw = request_json.map(Value::to_string).unwrap_or_default();
    analyze_text(config, request_json, &request_text_raw).await
}

/// Evaluate security for one actual tool action immediately before dispatch.
///
/// Requires an authenticated actor and target server.
pub async fn analyze_tool_action(
    config: &ToolSecurityConfig,
    tool_name: &str,
    arguments: &Value,
    authenticated_actor: &str,
    target_server: &str,
) -> ToolSecurityDecision {
    if authenticated_actor.trim().is_empty() {
        return ToolSecurityDecision {
            flagged: true,
            reason: Some("missing_authenticated_actor".to_string()),
            matched_entities: Vec::new(),
            provider_verdict: None,
        };
    }
    if target_server.trim().is_empty() {
        return ToolSecurityDecision {
            flagged: true,
            reason: Some("missing_target_server".to_string()),
            matched_entities: Vec::new(),
            provider_verdict: None,
        };
    }
    let action_json = serde_json::json!({
        "tool_name": tool_name,
        "arguments": arguments,
        "authenticated_actor": authenticated_actor,
        "target_server": target_server,
    });
    let request_text_raw = action_json.to_string();
    analyze_text(config, Some(&action_json), &request_text_raw).await
}

async fn analyze_text(
    config: &ToolSecurityConfig,
    request_json: Option<&Value>,
    request_text_raw: &str,
) -> ToolSecurityDecision {
    let request_text = request_text_raw.to_ascii_lowercase();

    if config.analysis_mode == AnalysisMode::External {
        if let Some(endpoint) = &config.firewall_endpoint {
            return analyze_with_external_firewall(
                config,
                endpoint,
                request_json,
                request_text_raw,
            )
            .await;
        }
    }

    for pattern in &config.blocked_patterns {
        let normalized_pattern = pattern.trim().to_ascii_lowercase();
        if !normalized_pattern.is_empty() && request_text.contains(&normalized_pattern) {
            return ToolSecurityDecision {
                flagged: true,
                reason: Some(format!("matched_blocked_pattern:{normalized_pattern}")),
                matched_entities: Vec::new(),
                provider_verdict: None,
            };
        }
    }

    for pattern in LOCAL_PATTERNS {
        if request_text.contains(pattern) {
            return ToolSecurityDecision {
                flagged: true,
                reason: Some(format!("matched_pattern:{pattern}")),
                matched_entities: Vec::new(),
                provider_verdict: None,
            };
        }
    }

    let matched_entities = blocked_findings(request_text_raw, &config.blocked_entity_types)
        .into_iter()
        .map(|finding| finding.entity_type)
        .collect::<Vec<_>>();

    if let Some(entity_type) = matched_entities.first() {
        return ToolSecurityDecision {
            flagged: true,
            reason: Some(format!("detected_entity:{entity_type}")),
            matched_entities,
            provider_verdict: None,
        };
    }

    ToolSecurityDecision {
        flagged: false,
        reason: None,
        matched_entities: Vec::new(),
        provider_verdict: None,
    }
}

async fn analyze_with_external_firewall(
    config: &ToolSecurityConfig,
    endpoint: &str,
    request_json: Option<&Value>,
    request_text_raw: &str,
) -> ToolSecurityDecision {
    let mut client_builder = reqwest::Client::builder();
    client_builder = client_builder.timeout(std::time::Duration::from_secs(3));
    let client = match client_builder.build() {
        Ok(client) => client,
        Err(error) => {
            return ToolSecurityDecision {
                flagged: config.fail_closed,
                reason: Some(format!("external_firewall_client_error:{error}")),
                matched_entities: Vec::new(),
                provider_verdict: Some(
                    if config.fail_closed { "deny" } else { "allow" }.to_string(),
                ),
            }
        }
    };

    let mut request = client.post(endpoint).json(&serde_json::json!({
        "request": request_json.cloned().unwrap_or(Value::Null),
        "entities": detect_entities(request_text_raw),
    }));

    if let Some(env_name) = &config.secret_key_env {
        if let Ok(api_key) = std::env::var(env_name) {
            if !api_key.trim().is_empty() {
                request = request.bearer_auth(api_key.trim());
            }
        }
    }

    let response = match request.send().await {
        Ok(response) => response,
        Err(error) => {
            return ToolSecurityDecision {
                flagged: config.fail_closed,
                reason: Some(format!("external_firewall_request_failed:{error}")),
                matched_entities: Vec::new(),
                provider_verdict: Some(
                    if config.fail_closed { "deny" } else { "allow" }.to_string(),
                ),
            }
        }
    };

    let payload: Value = match response.json().await {
        Ok(payload) => payload,
        Err(error) => {
            return ToolSecurityDecision {
                flagged: config.fail_closed,
                reason: Some(format!("external_firewall_invalid_response:{error}")),
                matched_entities: Vec::new(),
                provider_verdict: Some(
                    if config.fail_closed { "deny" } else { "allow" }.to_string(),
                ),
            }
        }
    };

    let (flagged, provider_verdict) = map_external_verdict(&payload);
    let matched_entities = payload
        .get("matched_entities")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    ToolSecurityDecision {
        flagged,
        reason: payload
            .get("reason")
            .and_then(|value| value.as_str())
            .map(ToString::to_string)
            .or_else(|| Some(format!("external_firewall_checked:{endpoint}"))),
        matched_entities,
        provider_verdict,
    }
}

pub fn map_external_verdict(payload: &Value) -> (bool, Option<String>) {
    let verdict = payload
        .get("verdict")
        .or_else(|| payload.get("action"))
        .and_then(Value::as_str)
        .map(|value| value.trim().to_ascii_lowercase());

    if let Some(verdict) = verdict {
        let flagged = matches!(
            verdict.as_str(),
            "deny" | "block" | "blocked" | "reject" | "rejected" | "flagged" | "review"
        );
        return (flagged, Some(verdict));
    }

    (
        payload
            .get("flagged")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
        None,
    )
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
    use axum::{extract::Json, http::HeaderMap, routing::post, Router};
    use serial_test::serial;
    use std::sync::{Arc, Mutex};

    async fn start_firewall_server(app: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        (format!("http://{addr}"), handle)
    }

    #[tokio::test]
    async fn local_analysis_matches_trimmed_case_insensitive_blocked_patterns() {
        let config = ToolSecurityConfig {
            blocked_patterns: vec!["  Delete Records  ".to_string()],
            ..Default::default()
        };

        let decision = analyze_request(
            &config,
            Some(&serde_json::json!({ "input": "please delete records now" })),
        )
        .await;

        assert!(decision.flagged);
        assert_eq!(
            decision.reason.as_deref(),
            Some("matched_blocked_pattern:delete records")
        );
    }

    #[tokio::test]
    async fn external_firewall_invalid_json_obeys_fail_open_setting() {
        let app = Router::new().route("/check", post(|| async { "not json" }));
        let (base_url, handle) = start_firewall_server(app).await;

        let config = ToolSecurityConfig {
            analysis_mode: AnalysisMode::External,
            firewall_endpoint: Some(format!("{base_url}/check")),
            fail_closed: false,
            ..Default::default()
        };

        let decision = analyze_request(
            &config,
            Some(&serde_json::json!({ "input": "benign request" })),
        )
        .await;

        handle.abort();

        assert!(!decision.flagged);
        assert_eq!(decision.provider_verdict.as_deref(), Some("allow"));
        assert!(decision
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("external_firewall_invalid_response"));
    }

    #[tokio::test]
    async fn analyze_tool_action_requires_authenticated_actor() {
        let decision = analyze_tool_action(
            &ToolSecurityConfig::default(),
            "search",
            &serde_json::json!({"q": "ok"}),
            "",
            "server-a",
        )
        .await;
        assert!(decision.flagged);
        assert_eq!(
            decision.reason.as_deref(),
            Some("missing_authenticated_actor")
        );
    }

    #[tokio::test]
    async fn analyze_tool_action_requires_target_server() {
        let decision = analyze_tool_action(
            &ToolSecurityConfig::default(),
            "search",
            &serde_json::json!({"q": "ok"}),
            "actor:1",
            "  ",
        )
        .await;
        assert!(decision.flagged);
        assert_eq!(decision.reason.as_deref(), Some("missing_target_server"));
    }

    #[tokio::test]
    async fn analyze_tool_action_flags_dangerous_argument_patterns() {
        let decision = analyze_tool_action(
            &ToolSecurityConfig::default(),
            "shell",
            &serde_json::json!({"cmd": "rm -rf /"}),
            "actor:1",
            "server-a",
        )
        .await;
        assert!(decision.flagged);
        assert!(decision
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("matched_pattern:rm -rf"));
    }
}
