// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::collections::{BTreeMap, BTreeSet};

use crate::persistence::sha256_hex;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{
    declarative_config::HostedGatewayLocalAccessConfig,
    server::EventSink,
    session::GatewaySessionContext,
    shell_actions::{classify_shell_command, ShellRiskLevel},
    work_reuse::{AgentToolChainMatch, ReuseMode, ReuseModeDecision},
    work_reuse_verifier::resolve_working_directory,
};

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct WorkReusePolicyDocument {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_reuse_modes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approval_required_actions: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub min_confidence_by_mode: BTreeMap<String, f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_replay_commands: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_network_write_allowed: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct WorkReusePolicyDecision {
    pub decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    pub reason_code: String,
    #[serde(default)]
    pub requested_mode: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_policy_ids: Vec<String>,
    #[serde(default)]
    pub effective_policy: WorkReusePolicyDocument,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
struct EvaluateWorkReusePolicyRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    org_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    team_id: Option<String>,
    git_repo: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_id: Option<String>,
    reuse_mode: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    requested_actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    verifier_commands: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    confidence_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_policy: Option<WorkReusePolicyDocument>,
}

fn normalize_scalar(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn session_identity_context_json(session: &GatewaySessionContext) -> Option<serde_json::Value> {
    let mut object = serde_json::Map::new();
    if let Some(org_id) = normalize_scalar(session._org_id.as_deref()) {
        object.insert("org_id".to_string(), json!(org_id));
    }
    if let Some(user_id) = normalize_scalar(session.user_id.as_deref()) {
        object.insert("user_id".to_string(), json!(user_id));
    }
    if let Some(team_id) = normalize_scalar(session.team_id.as_deref()) {
        object.insert("team_id".to_string(), json!(team_id));
    }
    if let Some(agent_id) = normalize_scalar(session.agent_id.as_deref()) {
        object.insert("agent_id".to_string(), json!(agent_id));
    }
    if let Some(key_id) = normalize_scalar(session._key_id.as_deref()) {
        object.insert("key_id".to_string(), json!(key_id.clone()));
        object.insert("api_token_id".to_string(), json!(key_id.clone()));
        object.insert("token_id".to_string(), json!(key_id));
    }
    if object.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(object))
    }
}

pub async fn evaluate_work_reuse_policy(
    sink: Option<&EventSink>,
    session: &GatewaySessionContext,
    local_access: Option<&HostedGatewayLocalAccessConfig>,
    working_directory_hint: Option<&str>,
    decision: &ReuseModeDecision,
    confidence_score: Option<f64>,
    tool_chain_match: Option<&AgentToolChainMatch>,
) -> WorkReusePolicyDecision {
    let request = match build_policy_request(
        session,
        local_access,
        working_directory_hint,
        decision,
        confidence_score,
        tool_chain_match,
    )
    .await
    {
        Ok(request) => request,
        Err(error) => {
            return fail_closed_policy_decision(
                decision.mode,
                "work_reuse.policy_request_build_failed",
                Some(error.to_string()),
            );
        }
    };

    let Some(sink) = sink else {
        return fail_closed_policy_decision(
            decision.mode,
            "work_reuse.policy_transport_unavailable",
            None,
        );
    };
    let Some(org_id) = normalize_scalar(session._org_id.as_deref()) else {
        return fail_closed_policy_decision(decision.mode, "work_reuse.policy_org_missing", None);
    };

    match evaluate_policy_request(sink, request.with_org_id(org_id)).await {
        Ok(response) => response,
        Err(error) => fail_closed_policy_decision(
            decision.mode,
            "work_reuse.policy_unavailable",
            Some(error.to_string()),
        ),
    }
}

async fn build_policy_request(
    session: &GatewaySessionContext,
    local_access: Option<&HostedGatewayLocalAccessConfig>,
    working_directory_hint: Option<&str>,
    decision: &ReuseModeDecision,
    confidence_score: Option<f64>,
    tool_chain_match: Option<&AgentToolChainMatch>,
) -> anyhow::Result<EvaluateWorkReusePolicyRequest> {
    let git_repo = normalize_scalar(
        session
            .git_context
            .as_ref()
            .and_then(|context| context.repo.as_deref()),
    )
    .context("missing git repo for work reuse policy evaluation")?;
    let mut requested_actions = BTreeSet::from([decision.mode.as_str().to_string()]);
    let verifier_commands = decision
        .verifier_commands
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();

    if let Some(config) = local_access {
        if let Some(working_directory) =
            resolve_working_directory(config, working_directory_hint, git_repo.as_str())
        {
            for command in verifier_commands.iter().take(3) {
                let risk = classify_shell_command(command, &working_directory, config).await;
                requested_actions.insert(shell_risk_action(risk).to_string());
                if command_looks_like_external_network_write(command) {
                    requested_actions.insert("external_network_write".to_string());
                }
            }
        } else if !verifier_commands.is_empty() {
            requested_actions.insert("critical_command".to_string());
        }
    } else if !verifier_commands.is_empty() {
        requested_actions.insert("critical_command".to_string());
    }

    let request_policy = tool_chain_match.map(|tool_chain| {
        apply_tool_chain_replay_policy_inputs(&mut requested_actions, tool_chain)
    });

    Ok(EvaluateWorkReusePolicyRequest {
        org_id: None,
        team_id: normalize_scalar(session.team_id.as_deref()),
        git_repo,
        agent_id: normalize_scalar(session.agent_id.as_deref()),
        reuse_mode: decision.mode.as_str().to_string(),
        requested_actions: requested_actions.into_iter().collect(),
        verifier_commands,
        confidence_score,
        request_policy,
    })
}

fn apply_tool_chain_replay_policy_inputs(
    requested_actions: &mut BTreeSet<String>,
    tool_chain: &AgentToolChainMatch,
) -> WorkReusePolicyDocument {
    requested_actions.insert("agent_tool_chain_replay".to_string());
    requested_actions.insert("tool_call_replay".to_string());
    for tool in &tool_chain.tool_calls {
        if let Some(tool_action) = normalized_tool_action(tool.tool_name.as_str()) {
            requested_actions.insert(tool_action);
        }
        if tool
            .provenance
            .get("side_effect")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            requested_actions.insert("side_effect_tool".to_string());
        }
        if tool
            .provenance
            .get("external_write")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            requested_actions.insert("external_network_write".to_string());
        }
        if tool
            .provenance
            .get("mutability_class")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| !value.eq_ignore_ascii_case("read_only"))
        {
            requested_actions.insert("mutating_tool".to_string());
        }
    }

    WorkReusePolicyDocument {
        blocked_actions: vec![
            "external_network_write".to_string(),
            "mutating_tool".to_string(),
            "side_effect_tool".to_string(),
        ],
        external_network_write_allowed: Some(false),
        ..WorkReusePolicyDocument::default()
    }
}

fn normalized_tool_action(tool_name: &str) -> Option<String> {
    let mut normalized = String::new();
    let mut last_was_separator = false;
    for ch in tool_name.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
            last_was_separator = false;
        } else if !last_was_separator {
            normalized.push('_');
            last_was_separator = true;
        }
    }
    let normalized = normalized.trim_matches('_');
    if normalized.is_empty() {
        None
    } else {
        Some(format!("tool:{normalized}"))
    }
}

async fn evaluate_policy_request(
    sink: &EventSink,
    request: EvaluateWorkReusePolicyRequest,
) -> anyhow::Result<WorkReusePolicyDecision> {
    let client = sink.machine_client()?;
    let url = format!(
        "{}/v1/gateway/work-reuse-policy/evaluate",
        sink.base_url().trim_end_matches('/'),
    );
    let response = client
        .post(url)
        .json(&request)
        .send()
        .await
        .context("work reuse policy evaluation failed")?;
    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        anyhow::bail!(
            "{}",
            super::machine_route_error::classify_and_format(
                "work-reuse-policy/evaluate",
                status,
                &text,
            )
        );
    }
    let mut decision = response
        .json::<WorkReusePolicyDecision>()
        .await
        .context("failed to decode work reuse policy response")?;
    if decision.requested_mode.is_empty() {
        decision.requested_mode = request.reuse_mode;
    }
    if decision.requested_actions.is_empty() {
        decision.requested_actions = request.requested_actions;
    }
    Ok(decision)
}

pub async fn emit_policy_decision_event(
    sink: Option<&EventSink>,
    request_id: &str,
    traceparent: &str,
    session: &GatewaySessionContext,
    decision: &WorkReusePolicyDecision,
) {
    let Some(sink) = sink else {
        return;
    };
    let identity_context = session_identity_context_json(session);
    let _ = sink
        .ingest_event(
            request_id,
            traceparent,
            json!({
                "event_type": "gateway.work_reuse.policy_decision",
                "request_id": request_id,
                "verdict": decision.decision,
                "reason_code": decision.reason_code,
                "config_version": "gateway-runtime",
                "environment": "gateway",
                "agent_id": session.agent_id.clone(),
                "identity_proof_method": "gateway_key",
                "identity_context": identity_context,
                "session_id": session.session_id.clone(),
                "metadata": {
                    "git_repo": session.git_context.as_ref().and_then(|value| value.repo.clone()),
                    "git_branch": session.git_context.as_ref().and_then(|value| value.branch.clone()),
                    "git_commit": session.git_context.as_ref().and_then(|value| value.commit.clone()),
                    "team_id": session.team_id.clone(),
                    "requested_mode": decision.requested_mode.clone(),
                    "requested_actions": decision.requested_actions.clone(),
                    "matched_policy_ids": decision.matched_policy_ids.clone(),
                    "effective_policy": decision.effective_policy.clone(),
                }
            }),
        )
        .await;
}

#[allow(clippy::too_many_arguments)] // Event emission keeps a stable sink/session/request call shape across gateway flows.
pub async fn emit_verifier_event(
    sink: Option<&EventSink>,
    request_id: &str,
    traceparent: &str,
    session: &GatewaySessionContext,
    phase: &str,
    verdict: &str,
    reason_code: &str,
    verifier_commands: &[String],
    verifier: Option<&super::work_reuse_verifier::ReuseVerifierSummary>,
) {
    let Some(sink) = sink else {
        return;
    };
    let identity_context = session_identity_context_json(session);
    let verifier_metadata = redacted_verifier_metadata(verifier_commands, verifier);
    let _ = sink
        .ingest_event(
            request_id,
            traceparent,
            json!({
                "event_type": format!("gateway.work_reuse.verifier.{phase}"),
                "request_id": request_id,
                "verdict": verdict,
                "reason_code": reason_code,
                "config_version": "gateway-runtime",
                "environment": "gateway",
                "agent_id": session.agent_id.clone(),
                "identity_proof_method": "gateway_key",
                "identity_context": identity_context,
                "session_id": session.session_id.clone(),
                "metadata": {
                    "git_repo": session.git_context.as_ref().and_then(|value| value.repo.clone()),
                    "git_branch": session.git_context.as_ref().and_then(|value| value.branch.clone()),
                    "git_commit": session.git_context.as_ref().and_then(|value| value.commit.clone()),
                    "team_id": session.team_id.clone(),
                    "verifier_command_count": verifier_commands.iter().take(3).count(),
                    "verifier_command_digests_sha256": verifier_commands
                        .iter()
                        .take(3)
                        .map(|command| sha256_hex(command.as_bytes()))
                        .collect::<Vec<_>>(),
                    "verifier": verifier_metadata,
                }
            }),
        )
        .await;
}

fn redacted_verifier_metadata(
    verifier_commands: &[String],
    verifier: Option<&super::work_reuse_verifier::ReuseVerifierSummary>,
) -> serde_json::Value {
    let command_digests = verifier_commands
        .iter()
        .take(3)
        .map(|command| sha256_hex(command.as_bytes()))
        .collect::<Vec<_>>();
    let Some(verifier) = verifier else {
        return json!({
            "attempted": verifier_commands.iter().take(3).count(),
            "executed": 0,
            "succeeded": false,
            "attempts": [],
            "command_digests_sha256": command_digests,
        });
    };

    let attempts = verifier
        .attempts
        .iter()
        .enumerate()
        .map(|(index, attempt)| {
            json!({
                "index": index,
                "command_digest_sha256": sha256_hex(attempt.command.as_bytes()),
                "risk_level": attempt.risk_level,
                "executed": attempt.executed,
                "succeeded": attempt.succeeded,
                "exit_code": attempt.exit_code,
                "timed_out": attempt.timed_out,
                "skipped": attempt.skipped_reason.is_some(),
                "skipped_reason_digest_sha256": attempt
                    .skipped_reason
                    .as_ref()
                    .map(|reason| sha256_hex(reason.as_bytes())),
                "stdout_present": attempt.stdout_preview.is_some(),
                "stderr_present": attempt.stderr_preview.is_some(),
            })
        })
        .collect::<Vec<_>>();

    json!({
        "attempted": verifier.attempted,
        "executed": verifier.executed,
        "succeeded": verifier.succeeded,
        "attempts": attempts,
        "command_digests_sha256": command_digests,
    })
}

impl EvaluateWorkReusePolicyRequest {
    fn with_org_id(mut self, org_id: String) -> Self {
        self.org_id = Some(org_id);
        self
    }
}

fn fail_closed_policy_decision(
    mode: ReuseMode,
    reason_code: &str,
    detail: Option<String>,
) -> WorkReusePolicyDecision {
    let mut requested_actions = vec![mode.as_str().to_string()];
    if let Some(detail) = detail {
        requested_actions.push(detail);
    }
    WorkReusePolicyDecision {
        decision: "approval_required".to_string(),
        policy_id: None,
        reason_code: reason_code.to_string(),
        requested_mode: mode.as_str().to_string(),
        requested_actions,
        matched_policy_ids: Vec::new(),
        effective_policy: WorkReusePolicyDocument::default(),
    }
}

fn shell_risk_action(level: ShellRiskLevel) -> &'static str {
    match level {
        ShellRiskLevel::Safe => "safe_command",
        ShellRiskLevel::Moderate => "moderate_command",
        ShellRiskLevel::Destructive => "destructive_command",
        ShellRiskLevel::Critical => "critical_command",
    }
}

fn command_looks_like_external_network_write(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    [
        "curl ", "wget ", "scp ", "rsync ", "git push", "http://", "https://",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
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

    #[test]
    fn fail_closed_policy_decision_requires_approval() {
        let decision = fail_closed_policy_decision(
            ReuseMode::ReplayCommands,
            "work_reuse.policy_unavailable",
            None,
        );

        assert_eq!(decision.decision, "approval_required");
        assert_eq!(decision.reason_code, "work_reuse.policy_unavailable");
    }

    #[test]
    fn external_network_write_detection_matches_common_commands() {
        assert!(command_looks_like_external_network_write(
            "curl -X POST https://example.com",
        ));
        assert!(!command_looks_like_external_network_write(
            "cargo nextest run --test work_reuse",
        ));
    }

    #[test]
    fn verifier_metadata_redacts_commands_paths_and_output() {
        let commands = vec!["cargo nextest run --test secret_lane".to_string()];
        let verifier = super::super::work_reuse_verifier::ReuseVerifierSummary {
            working_directory: Some("/tmp/private-project".to_string()),
            attempted: 1,
            executed: 1,
            succeeded: false,
            attempts: vec![super::super::work_reuse_verifier::ReuseVerifierAttempt {
                command: commands[0].clone(),
                risk_level: "safe".to_string(),
                executed: true,
                succeeded: false,
                exit_code: Some(1),
                timed_out: Some(false),
                skipped_reason: Some("private failure reason".to_string()),
                stdout_preview: Some("stdout secret preview".to_string()),
                stderr_preview: Some("stderr secret preview".to_string()),
            }],
        };

        let metadata = redacted_verifier_metadata(&commands, Some(&verifier));
        let serialized = serde_json::to_string(&metadata).expect("metadata json");

        assert!(!serialized.contains("secret_lane"));
        assert!(!serialized.contains("/tmp/private-project"));
        assert!(!serialized.contains("stdout secret preview"));
        assert!(!serialized.contains("stderr secret preview"));
        assert!(!serialized.contains("private failure reason"));
        assert_eq!(metadata["attempted"], 1);
        assert_eq!(metadata["attempts"][0]["exit_code"], 1);
        assert!(metadata["attempts"][0]["command_digest_sha256"]
            .as_str()
            .is_some_and(|value| value.len() == 64));
    }
}
