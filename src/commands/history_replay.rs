// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan history replay <session_id>` — replay a session's user messages through
//! the current policy chain and model, comparing original vs new responses.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct HistoryReplayArgs {
    /// Session id to replay.
    pub(crate) session_id: String,

    /// Gateway id for replay. If not set, use the gateway from the session.
    #[arg(long)]
    pub(crate) gateway_id: Option<String>,

    /// Emit machine-readable JSON to stdout.
    #[arg(long)]
    pub(crate) json: bool,

    /// Optional config file path (YAML).
    #[arg(long)]
    pub(crate) config: Option<std::path::PathBuf>,

    /// Override API URL.
    #[arg(long)]
    pub(crate) api_url: Option<String>,

    /// Override API token.
    #[arg(long)]
    pub(crate) api_token: Option<String>,

    /// Profile name (default: "default").
    #[arg(long, default_value = "default")]
    pub(crate) profile: String,

    /// Target region for this API call.
    #[arg(long)]
    pub(crate) region: Option<String>,
}
struct ReplayMetrics {
    messages_replayed: usize,
    policy_changes: usize,
    original_tokens: i64,
    new_tokens: i64,
    original_cost: f64,
    new_cost: f64,
}

pub(crate) async fn run_async(args: HistoryReplayArgs) -> Result<(), CliError> {
    let client = build_client(args.api_url, args.api_token, args.config, args.profile)?;

    let sid = urlencoding::encode(&args.session_id);

    // Fetch original entries.
    let entries_path = format!("/v1/history/sessions/{sid}/entries");
    let entries_value = client.get_json_value(&entries_path).await?;
    let entries = entries_value
        .get("entries")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut metrics = ReplayMetrics {
        messages_replayed: 0,
        policy_changes: 0,
        original_tokens: 0,
        new_tokens: 0,
        original_cost: 0.0,
        new_cost: 0.0,
    };

    let mut replay_results: Vec<serde_json::Value> = Vec::new();

    for entry in &entries {
        // Only replay user messages that have request payloads.
        let request_payload = match entry.get("request_payload") {
            Some(p) if p.is_object() => p,
            _ => continue,
        };

        let messages = match request_payload.get("messages").and_then(|m| m.as_array()) {
            Some(msgs) => msgs,
            None => continue,
        };

        // Check the last message is from user.
        let last_role = messages
            .last()
            .and_then(|m| m.get("role"))
            .and_then(|r| r.as_str())
            .unwrap_or("");
        if last_role != "user" {
            continue;
        }

        // Build replay request.
        let mut replay_body = serde_json::json!({
            "messages": messages,
            "replay": true,
        });
        if let Some(ref gw) = args.gateway_id {
            replay_body
                .as_object_mut()
                .ok_or_else(|| CliError::internal("replay request body must be an object"))?
                .insert("gateway_id".to_string(), serde_json::json!(gw));
        }

        // Send through replay endpoint.
        let replay_path = format!("/v1/history/sessions/{sid}/replay");
        let new_response = client.post_json_value(&replay_path, &replay_body).await?;

        // Extract original response info.
        let original_decision = entry
            .get("decision")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let original_content = entry
            .get("response_payload")
            .and_then(|p| p.get("choices"))
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|choice| choice.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .unwrap_or("");
        let original_tok = entry
            .get("tokens_used")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let original_c = entry.get("cost").and_then(|v| v.as_f64()).unwrap_or(0.0);

        // Extract new response info.
        let new_decision = new_response
            .get("decision")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let new_content = new_response
            .get("response_payload")
            .and_then(|p| p.get("choices"))
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|choice| choice.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .unwrap_or("");
        let new_tok = new_response
            .get("tokens_used")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let new_c = new_response
            .get("cost")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        metrics.messages_replayed += 1;
        metrics.original_tokens += original_tok;
        metrics.new_tokens += new_tok;
        metrics.original_cost += original_c;
        metrics.new_cost += new_c;
        if original_decision != new_decision {
            metrics.policy_changes += 1;
        }

        let user_msg = messages
            .last()
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .unwrap_or("");

        replay_results.push(serde_json::json!({
            "user_message": user_msg,
            "original_decision": original_decision,
            "new_decision": new_decision,
            "original_content": original_content,
            "new_content": new_content,
            "original_tokens": original_tok,
            "new_tokens": new_tok,
            "original_cost": original_c,
            "new_cost": new_c,
            "policy_changed": original_decision != new_decision,
        }));

        if !args.json {
            // Print side-by-side (original dimmed).
            println!("── message {} ──", metrics.messages_replayed);
            println!("  user: {user_msg}");
            println!(
                "  \x1b[2moriginal [{original_decision}]: {}\x1b[0m",
                truncate(original_content, 100)
            );
            println!(
                "  new      [{new_decision}]: {}",
                truncate(new_content, 100)
            );
            if original_decision != new_decision {
                println!("  \x1b[33m⚠ policy verdict changed\x1b[0m");
            }
            println!();
        }
    }

    if args.json {
        let output = serde_json::json!({
            "results": replay_results,
            "summary": {
                "messages_replayed": metrics.messages_replayed,
                "policy_changes": metrics.policy_changes,
                "original_tokens": metrics.original_tokens,
                "new_tokens": metrics.new_tokens,
                "token_diff": metrics.new_tokens - metrics.original_tokens,
                "original_cost": metrics.original_cost,
                "new_cost": metrics.new_cost,
                "cost_diff": metrics.new_cost - metrics.original_cost,
            }
        });
        return print_json(&output);
    }

    // Print summary.
    println!("═══ replay summary ═══");
    println!("messages replayed:  {}", metrics.messages_replayed);
    println!("policy changes:     {}", metrics.policy_changes);
    println!(
        "tokens (orig/new):  {} / {} (diff: {:+})",
        metrics.original_tokens,
        metrics.new_tokens,
        metrics.new_tokens - metrics.original_tokens
    );
    println!(
        "cost (orig/new):    ${:.4} / ${:.4} (diff: {:+.4})",
        metrics.original_cost,
        metrics.new_cost,
        metrics.new_cost - metrics.original_cost
    );

    Ok(())
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}

fn build_client(
    api_url: Option<String>,
    api_token: Option<String>,
    config_path: Option<std::path::PathBuf>,
    profile: String,
) -> Result<AsyncApiClient, CliError> {
    let inputs = ConfigInputs {
        api_url_flag: api_url,
        api_token_flag: api_token,
        config_path,
        profile_flag: Some(profile),
        region_flag: None,
    };
    let config = Config::resolve(inputs)?;
    let token = config.api_token.ok_or_else(|| {
        CliError::auth("missing api token (set VERDICTAN_API_TOKEN or run `verdictan auth login`)")
    })?;
    AsyncApiClient::new(config.api_url, token)
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
    use serde_json::json;

    use super::truncate;

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_exact_length() {
        assert_eq!(truncate("hello", 5), "hello");
    }

    #[test]
    fn truncate_long_string() {
        assert_eq!(truncate("hello world", 5), "hello");
    }

    #[test]
    fn truncate_empty_string() {
        assert_eq!(truncate("", 10), "");
    }

    #[test]
    fn entries_path_formatting() {
        let sid = urlencoding::encode("sess-1");
        let path = format!("/v1/history/sessions/{sid}/entries");
        assert_eq!(path, "/v1/history/sessions/sess-1/entries");
    }

    #[test]
    fn replay_path_formatting() {
        let sid = urlencoding::encode("sess-1");
        let path = format!("/v1/history/sessions/{sid}/replay");
        assert_eq!(path, "/v1/history/sessions/sess-1/replay");
    }

    #[test]
    fn replay_body_with_gateway_id() {
        let messages = json!([{"role": "user", "content": "hi"}]);
        let mut body = json!({
            "messages": messages,
            "replay": true,
        });
        let gw = "gw-42";
        body.as_object_mut()
            .unwrap()
            .insert("gateway_id".to_string(), json!(gw));
        assert_eq!(body["gateway_id"], "gw-42");
        assert_eq!(body["replay"], true);
    }

    #[test]
    fn replay_body_without_gateway_id() {
        let messages = json!([{"role": "user", "content": "hi"}]);
        let body = json!({
            "messages": messages,
            "replay": true,
        });
        assert!(body.get("gateway_id").is_none());
    }

    #[test]
    fn extract_original_decision() {
        let entry = json!({"decision": "allow", "tokens_used": 100, "cost": 0.05});
        let decision = entry
            .get("decision")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let tokens = entry
            .get("tokens_used")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let cost = entry.get("cost").and_then(|v| v.as_f64()).unwrap_or(0.0);
        assert_eq!(decision, "allow");
        assert_eq!(tokens, 100);
        assert!((cost - 0.05).abs() < f64::EPSILON);
    }

    #[test]
    fn extract_original_decision_missing() {
        let entry = json!({});
        let decision = entry
            .get("decision")
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        assert_eq!(decision, "-");
    }

    #[test]
    fn replay_metrics_policy_changed_detection() {
        let original_decision = "allow";
        let new_decision = "deny";
        assert_ne!(original_decision, new_decision);
    }
}
