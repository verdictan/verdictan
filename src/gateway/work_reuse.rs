// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::task_novelty::{NoveltyClass, TaskNoveltyAssessment};
use super::work_reuse_policy::WorkReusePolicyDecision;

pub use super::work_reuse_verifier::ReuseVerifierSummary;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReuseMode {
    AnswerFromReceipt,
    ReplayCommands,
    AdaptPreviousPatch,
    RunKnownVerifier,
    #[default]
    OpenFreshInvestigation,
}

impl ReuseMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AnswerFromReceipt => "answer_from_receipt",
            Self::ReplayCommands => "replay_commands",
            Self::AdaptPreviousPatch => "adapt_previous_patch",
            Self::RunKnownVerifier => "run_known_verifier",
            Self::OpenFreshInvestigation => "open_fresh_investigation",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ReuseModeDecision {
    pub mode: ReuseMode,
    pub novelty_class: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_receipt_id: Option<String>,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verifier_commands: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RuntimeReuseOutcome {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub novelty_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_receipt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<ReuseModeDecision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_decision: Option<WorkReusePolicyDecision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier: Option<ReuseVerifierSummary>,
    #[serde(default)]
    pub tool_chain_hit: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_names: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avoided_tool_executions: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avoided_model_calls: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reuse_applied: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay_success: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_denied: Option<bool>,
    pub block_injected: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AgentToolCallTraceMatch {
    pub agent_tool_call_trace_id: String,
    pub tool_name: String,
    pub tool_status: String,
    pub policy_decision: String,
    #[serde(default)]
    pub duration_ms: Option<i64>,
    #[serde(default)]
    pub provenance: serde_json::Value,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AgentToolChainMatch {
    pub work_receipt_id: String,
    pub agent_call_trace_id: String,
    #[serde(default)]
    pub team_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    pub git_repo: String,
    #[serde(default)]
    pub git_branch: Option<String>,
    #[serde(default)]
    pub git_commit: Option<String>,
    #[serde(default)]
    pub match_novelty_class: String,
    #[serde(default)]
    pub exact_hash_match: bool,
    #[serde(default)]
    pub matched_reasons: Vec<String>,
    #[serde(default)]
    pub tool_calls: Vec<AgentToolCallTraceMatch>,
}

pub fn select_reuse_mode(
    assessment: Option<&TaskNoveltyAssessment>,
    tool_chain_match: Option<&AgentToolChainMatch>,
    local_access_enabled: bool,
) -> Option<ReuseModeDecision> {
    let assessment = assessment?;
    let matched = assessment.matched_receipt.as_ref();
    let novelty_class = assessment.novelty_class.as_str().to_string();
    let Some(matched) = matched else {
        return Some(ReuseModeDecision {
            mode: ReuseMode::OpenFreshInvestigation,
            novelty_class,
            matched_receipt_id: None,
            reason: "no prior verified receipt matched the current task".to_string(),
            verifier_commands: Vec::new(),
        });
    };

    let verifier_commands = matched
        .commands
        .iter()
        .map(|command| command.command_text.trim().to_string())
        .filter(|command| !command.is_empty())
        .take(3)
        .collect::<Vec<_>>();
    let has_summary = matched
        .patch_summary
        .as_deref()
        .map(str::trim)
        .is_some_and(|value| !value.is_empty());
    let has_file_overlap = overlapping_paths(
        &assessment.request.file_paths,
        &matched
            .files
            .iter()
            .map(|file| file.file_path.clone())
            .collect::<Vec<_>>(),
    );
    let is_verified = matched.verification_status == "verified";
    let exact = assessment.novelty_class == NoveltyClass::ExactRepeat;
    let near = assessment.novelty_class == NoveltyClass::NearRepeat;
    let known = assessment.novelty_class == NoveltyClass::KnownPatternNewLocation;
    let reusable_tool_chain = tool_chain_match
        .filter(|candidate| tool_chain_supports_autonomous_reuse(assessment, candidate));

    let (mode, reason) = if exact && is_verified && matched.confidence_score >= 0.90 && has_summary
    {
        (
            ReuseMode::AnswerFromReceipt,
            if reusable_tool_chain.is_some() {
                "exact verified receipt and agent/tool chain remain reusable".to_string()
            } else {
                "exact verified receipt includes a confident patch summary".to_string()
            },
        )
    } else if reusable_tool_chain.is_some()
        && local_access_enabled
        && (exact || near)
        && is_verified
        && matched.confidence_score >= 0.82
        && !verifier_commands.is_empty()
    {
        (
            ReuseMode::ReplayCommands,
            "matched verified receipt and agent/tool chain remain policy-eligible for autonomous replay"
                .to_string(),
        )
    } else if local_access_enabled
        && (exact || near)
        && is_verified
        && matched.confidence_score >= 0.82
        && !verifier_commands.is_empty()
    {
        (
            ReuseMode::ReplayCommands,
            "matched receipt carries reusable verifier commands".to_string(),
        )
    } else if (near || known) && is_verified && matched.confidence_score >= 0.88 && has_file_overlap
    {
        (
            ReuseMode::AdaptPreviousPatch,
            "matched receipt overlaps the same file scope and needs adaptation".to_string(),
        )
    } else if local_access_enabled
        && is_verified
        && matched.confidence_score >= 0.85
        && !verifier_commands.is_empty()
    {
        (
            ReuseMode::RunKnownVerifier,
            "only the prior verifier is reusable without replaying the whole receipt".to_string(),
        )
    } else {
        (
            ReuseMode::OpenFreshInvestigation,
            "prior evidence is too weak for autonomous reuse".to_string(),
        )
    };

    Some(ReuseModeDecision {
        mode,
        novelty_class,
        matched_receipt_id: Some(matched.receipt_id.clone()),
        reason,
        verifier_commands,
    })
}

fn tool_chain_supports_autonomous_reuse(
    assessment: &TaskNoveltyAssessment,
    candidate: &AgentToolChainMatch,
) -> bool {
    if candidate.git_repo.trim() != assessment.request.git_repo.trim() {
        return false;
    }
    if assessment.request.team_id.as_deref() != candidate.team_id.as_deref() {
        return false;
    }
    if assessment.request.agent_id.as_deref() != candidate.agent_id.as_deref() {
        return false;
    }
    if assessment.request.git_branch.as_deref() != candidate.git_branch.as_deref() {
        return false;
    }
    let has_scope_evidence = candidate.exact_hash_match
        || candidate.matched_reasons.iter().any(|reason| {
            matches!(
                reason.as_str(),
                "git_commit" | "file_scope" | "symbol_scope" | "task_fingerprint"
            )
        });
    if !has_scope_evidence || candidate.tool_calls.is_empty() {
        return false;
    }
    candidate.tool_calls.iter().all(tool_call_is_reusable)
}

fn tool_call_is_reusable(tool_call: &AgentToolCallTraceMatch) -> bool {
    let normalized_status = tool_call.tool_status.trim().to_ascii_lowercase();
    let normalized_policy = tool_call.policy_decision.trim().to_ascii_lowercase();
    if !matches!(
        normalized_status.as_str(),
        "success" | "succeeded" | "completed" | "ok"
    ) {
        return false;
    }
    if !matches!(normalized_policy.as_str(), "allow" | "allowed") {
        return false;
    }
    if tool_call
        .provenance
        .get("side_effect")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return false;
    }
    if tool_call
        .provenance
        .get("external_write")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return false;
    }
    if tool_call
        .provenance
        .get("mutability_class")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value.eq_ignore_ascii_case("mutating"))
    {
        return false;
    }
    true
}

pub fn build_reuse_context_block(
    assessment: &TaskNoveltyAssessment,
    decision: &ReuseModeDecision,
    verifier: Option<&ReuseVerifierSummary>,
) -> Option<String> {
    if decision.mode == ReuseMode::OpenFreshInvestigation {
        return None;
    }
    let matched = assessment.matched_receipt.as_ref()?;
    let mut lines = vec![
        format!(
            "Verdictan work reuse: mode={} novelty={} receipt={}",
            decision.mode.as_str(),
            decision.novelty_class,
            matched.receipt_id
        ),
        format!("Reason: {}", decision.reason),
    ];
    if !matched.intent.trim().is_empty() {
        lines.push(format!("Prior intent: {}", matched.intent.trim()));
    }
    if let Some(summary) = matched.patch_summary.as_deref() {
        if !summary.trim().is_empty() {
            lines.push(format!("Patch summary: {}", summary.trim()));
        }
    }
    if !matched.final_outcome.trim().is_empty() {
        lines.push(format!("Outcome: {}", matched.final_outcome.trim()));
    }
    lines.push(format!(
        "Verification: {} ({:.2})",
        matched.verification_status, matched.confidence_score
    ));
    if !matched.files.is_empty() {
        lines.push(format!(
            "Files: {}",
            matched
                .files
                .iter()
                .map(|file| file.file_path.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !matched.symbols.is_empty() {
        lines.push(format!(
            "Symbols: {}",
            matched
                .symbols
                .iter()
                .map(|symbol| symbol.symbol_name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !decision.verifier_commands.is_empty() {
        lines.push(format!(
            "Known verifier commands: {}",
            decision.verifier_commands.join(" | ")
        ));
    }
    if let Some(verifier) = verifier {
        let status = if verifier.succeeded {
            "passed"
        } else {
            "failed_or_skipped"
        };
        lines.push(format!("Verifier status: {status}"));
    }
    Some(lines.join("\n"))
}

pub fn inject_reuse_block_into_chat_request(request: &mut serde_json::Value, block: &str) -> bool {
    let Some(messages) = request
        .get_mut("messages")
        .and_then(|value| value.as_array_mut())
    else {
        return false;
    };
    if block.trim().is_empty() {
        return false;
    }
    messages.insert(
        0,
        serde_json::json!({
            "role": "system",
            "content": block,
            "_verdictan_work_reuse": true,
        }),
    );
    true
}

pub fn inject_reuse_block_into_responses_request(
    request: &mut serde_json::Value,
    block: &str,
) -> bool {
    if block.trim().is_empty() {
        return false;
    }

    let Some(input) = request.get_mut("input") else {
        request["input"] = serde_json::json!([{
            "role": "system",
            "content": block,
            "_verdictan_work_reuse": true,
        }]);
        return true;
    };
    if let Some(existing) = input.as_str() {
        *input = serde_json::json!([
            {
                "role": "system",
                "content": block,
                "_verdictan_work_reuse": true,
            },
            existing,
        ]);
        return true;
    }
    let Some(items) = input.as_array_mut() else {
        return false;
    };
    items.insert(
        0,
        serde_json::json!({
            "role": "system",
            "content": block,
            "_verdictan_work_reuse": true,
        }),
    );
    true
}

fn overlapping_paths(left: &[String], right: &[String]) -> bool {
    let left = canonical_set(left);
    let right = canonical_set(right);
    left.iter().any(|path| right.contains(path))
}

fn canonical_set(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .map(|value| {
            value
                .trim()
                .replace('\\', "/")
                .trim_start_matches("./")
                .trim_matches('/')
                .to_ascii_lowercase()
        })
        .filter(|value| !value.is_empty())
        .collect()
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
    use crate::gateway::task_novelty::{
        TaskFingerprint, TaskNoveltyRequest, WorkReceiptCommand, WorkReceiptFile, WorkReceiptMatch,
    };

    fn assessment() -> TaskNoveltyAssessment {
        TaskNoveltyAssessment {
            novelty_class: NoveltyClass::NearRepeat,
            matched_receipt: Some(WorkReceiptMatch {
                receipt_id: "r-1".to_string(),
                intent: "Fix gateway replay".to_string(),
                patch_summary: Some("Reuse the previous verifier lane".to_string()),
                final_outcome: "Verifier stabilized".to_string(),
                verification_status: "verified".to_string(),
                confidence_score: 0.95,
                files: vec![WorkReceiptFile {
                    file_path: "cli/src/gateway/server.rs".to_string(),
                }],
                commands: vec![WorkReceiptCommand {
                    command_text: "cargo nextest run --test gateway_features_unit".to_string(),
                    ..WorkReceiptCommand::default()
                }],
                ..WorkReceiptMatch::default()
            }),
            candidate_receipts: Vec::new(),
            request: TaskNoveltyRequest {
                git_repo: "verdictan/verdictan".to_string(),
                file_paths: vec!["cli/src/gateway/server.rs".to_string()],
                fingerprint: TaskFingerprint::default(),
                ..TaskNoveltyRequest::default()
            },
        }
    }

    #[test]
    fn select_reuse_mode_prefers_replay_for_verified_near_repeat() {
        let decision = select_reuse_mode(Some(&assessment()), None, true).expect("decision");

        assert_eq!(decision.mode, ReuseMode::ReplayCommands);
        assert_eq!(decision.matched_receipt_id.as_deref(), Some("r-1"));
    }

    #[test]
    fn build_reuse_context_block_includes_verifier_commands() {
        let assessment = assessment();
        let decision = select_reuse_mode(Some(&assessment), None, true).expect("decision");
        let block = build_reuse_context_block(&assessment, &decision, None).expect("block");

        assert!(block.contains("mode=replay_commands"));
        assert!(block.contains("Known verifier commands"));
    }
}
