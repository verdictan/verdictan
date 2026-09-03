// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan history condense` — produce a condensed history artifact locally from
//! fetched session entries without automatically binding it.
//!
//! This command fetches one or more sessions from the API, applies the same
//! deterministic `extract` condensation algorithm as the server-side
//! `history condense` handler, and writes the result to stdout or a file.
//! The `condense` and `hybrid` strategies are accepted but both fall back to
//! the deterministic `extract` path because they require a live LLM provider
//! call that should not run in the CLI request hot path.
//!
//! Client-side `--since`/`--until` filtering is applied after fetching because
//! the API does not expose those query parameters on the sessions list endpoint.
//!
//! # Module wiring
//! Add `pub(crate) mod history_condense;` to `cli/src/commands/mod.rs` to
//! activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;
fn estimate_tokens(text: &str) -> u32 {
    (text.split_whitespace().count() as f64 * 1.3).ceil() as u32
}

fn synthesize_condensed_text(
    entries: &[serde_json::Value],
    allowed_only: bool,
    include_blocked: bool,
    target_max_tokens: u32,
) -> String {
    let max_chars = (target_max_tokens as usize) * 4;
    let mut buf = String::new();
    for entry in entries {
        let verdict = entry
            .get("verdict")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        if allowed_only && verdict != "allowed" {
            continue;
        }
        if !include_blocked && verdict == "blocked" {
            continue;
        }
        let role = entry
            .get("role")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let content = entry.get("content").and_then(|v| v.as_str()).unwrap_or("");
        if content.trim().is_empty() {
            continue;
        }
        let line = format!("{role}: {content}\n");
        if buf.len() + line.len() > max_chars {
            break;
        }
        buf.push_str(&line);
    }
    buf
}

#[derive(Debug, Args)]
pub(crate) struct HistoryCondenseArgs {
    /// Condense a specified session by id.
    #[arg(long)]
    pub(crate) session_id: Option<String>,

    /// Scope filter when --session-id is not set.
    #[arg(long, value_parser = ["user", "team", "org"])]
    pub(crate) scope: Option<String>,

    /// Team id filter.
    #[arg(long)]
    pub(crate) team_id: Option<String>,

    /// Agent id filter.
    #[arg(long)]
    pub(crate) agent_id: Option<String>,

    /// Include only sessions after this RFC3339 timestamp (client-side).
    #[arg(long)]
    pub(crate) since: Option<String>,

    /// Include only sessions before this RFC3339 timestamp (client-side).
    #[arg(long)]
    pub(crate) until: Option<String>,

    /// Condensation strategy. `condense` and `hybrid` apply the same
    /// deterministic extraction as `extract` in the CLI (no LLM call).
    #[arg(long, default_value = "extract",
          value_parser = ["extract", "condense", "hybrid"])]
    pub(crate) strategy: String,

    /// Target token budget.
    #[arg(long, default_value_t = 1200)]
    pub(crate) target_max_tokens: u32,

    /// Include only allowed entries.
    #[arg(long, default_value_t = true)]
    pub(crate) allowed_only: bool,

    /// Also include blocked entries.
    #[arg(long)]
    pub(crate) include_blocked: bool,

    /// Write the condensed artifact to this path, not stdout.
    #[arg(long)]
    pub(crate) output: Option<std::path::PathBuf>,

    /// Print counts without writing output.
    #[arg(long)]
    pub(crate) dry_run: bool,

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
pub(crate) async fn run_async(args: HistoryCondenseArgs) -> Result<(), CliError> {
    let since_dt = args
        .since
        .as_deref()
        .map(parse_rfc3339)
        .transpose()
        .map_err(|e| CliError::user(format!("invalid --since: {e}")))?;
    let until_dt = args
        .until
        .as_deref()
        .map(parse_rfc3339)
        .transpose()
        .map_err(|e| CliError::user(format!("invalid --until: {e}")))?;

    let inputs = ConfigInputs {
        api_url_flag: args.api_url,
        api_token_flag: args.api_token,
        config_path: args.config,
        profile_flag: Some(args.profile),
        region_flag: args.region,
    };
    let config = Config::resolve(inputs)?;
    let api_token = config.api_token.ok_or_else(|| {
        CliError::auth("missing api token (set VERDICTAN_API_TOKEN or run `verdictan auth login`)")
    })?;
    let client = AsyncApiClient::new(config.api_url, api_token)?.with_region(config.region.clone());

    // Gather target sessions.
    let session_ids = if let Some(id) = &args.session_id {
        vec![id.clone()]
    } else {
        fetch_matching_session_ids(
            &client,
            args.scope.as_deref(),
            args.team_id.as_deref(),
            args.agent_id.as_deref(),
            since_dt.as_ref(),
            until_dt.as_ref(),
        )
        .await?
    };

    if session_ids.is_empty() {
        return Err(CliError::user(
            "no matching history sessions found; adjust --scope, --since, or --until filters",
        ));
    }

    // Fetch entries for each session.
    let mut all_entries: Vec<serde_json::Value> = Vec::new();
    for sid in &session_ids {
        let entries_path = format!("/v1/history/sessions/{sid}/entries");
        match client.get_json_value(&entries_path).await {
            Ok(v) => {
                if let Some(entries) = v.get("entries").and_then(|e| e.as_array()) {
                    all_entries.extend(entries.iter().cloned());
                }
            }
            Err(e) => {
                eprintln!("warning: could not fetch entries for session {sid}: {e}");
            }
        }
    }

    if all_entries.is_empty() {
        return Err(CliError::user("no history entries available to condense"));
    }

    let summary_text = synthesize_condensed_text(
        &all_entries,
        args.allowed_only,
        args.include_blocked,
        args.target_max_tokens,
    );

    if summary_text.trim().is_empty() {
        return Err(CliError::user(
            "no eligible entries to synthesize (check --allowed-only and --include-blocked flags)",
        ));
    }

    let token_estimate = estimate_tokens(&summary_text);

    if args.dry_run {
        let info = serde_json::json!({
            "dry_run": true,
            "strategy": args.strategy,
            "sessions": session_ids,
            "entries_fetched": all_entries.len(),
            "token_estimate": token_estimate,
            "target_max_tokens": args.target_max_tokens,
        });
        if args.json {
            print_json(&info)?;
        } else {
            println!("dry-run: strategy={}", args.strategy);
            println!("  sessions:         {}", session_ids.len());
            println!("  entries_fetched:  {}", all_entries.len());
            println!("  token_estimate:   {token_estimate}");
        }
        return Ok(());
    }

    let artifact = serde_json::json!({
        "load_kind": "condense_artifact",
        "strategy": args.strategy,
        "source": {
            "session_ids": session_ids,
            "entries_fetched": all_entries.len(),
        },
        "condensation": {
            "strategy": args.strategy,
            "target_max_tokens": args.target_max_tokens,
            "token_estimate": token_estimate,
            "allowed_only": args.allowed_only,
            "include_blocked": args.include_blocked,
        },
        "units": [{
            "unit_id": "summary",
            "content": summary_text,
            "content_mime": "text/plain",
            "labels": ["condensed_history", "history"],
        }],
    });

    match &args.output {
        Some(path) => {
            let json = serde_json::to_string_pretty(&artifact)
                .map_err(|e| CliError::internal(format!("failed to serialize artifact: {e}")))?;
            std::fs::write(path, json).map_err(|e| {
                CliError::user(format!("failed to write to {}: {e}", path.display()))
            })?;
            if !args.json {
                println!("artifact: {}", path.display());
                println!("strategy: {}", args.strategy);
                println!("sessions: {}", session_ids.len());
                println!("tokens:   ~{token_estimate}");
            }
        }
        None => {
            if args.json {
                print_json(&artifact)?;
            } else {
                println!("{summary_text}");
            }
        }
    }

    Ok(())
}

async fn fetch_matching_session_ids(
    client: &AsyncApiClient,
    scope: Option<&str>,
    team_id: Option<&str>,
    agent_id: Option<&str>,
    since: Option<&chrono::DateTime<chrono::Utc>>,
    until: Option<&chrono::DateTime<chrono::Utc>>,
) -> Result<Vec<String>, CliError> {
    let path = build_sessions_path(scope, team_id, agent_id);
    let value = client.get_json_value(&path).await?;
    Ok(matching_session_ids_from_value(&value, since, until))
}

fn parse_rfc3339(s: &str) -> Result<chrono::DateTime<chrono::Utc>, String> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| e.to_string())
}

fn build_sessions_path(
    scope: Option<&str>,
    team_id: Option<&str>,
    agent_id: Option<&str>,
) -> String {
    let mut query_parts = Vec::new();
    if let Some(scope) = scope {
        query_parts.push(format!("scope={}", urlencoding::encode(scope)));
    }
    if let Some(team_id) = team_id {
        query_parts.push(format!("team_id={}", urlencoding::encode(team_id)));
    }
    if let Some(agent_id) = agent_id {
        query_parts.push(format!("agent_id={}", urlencoding::encode(agent_id)));
    }

    if query_parts.is_empty() {
        "/v1/history/sessions".to_string()
    } else {
        format!("/v1/history/sessions?{}", query_parts.join("&"))
    }
}

fn matching_session_ids_from_value(
    value: &serde_json::Value,
    since: Option<&chrono::DateTime<chrono::Utc>>,
    until: Option<&chrono::DateTime<chrono::Utc>>,
) -> Vec<String> {
    value
        .get("sessions")
        .and_then(|s| s.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|session| {
            let activity = session
                .get("last_activity_at")
                .and_then(|v| v.as_str())
                .and_then(|s| parse_rfc3339(s).ok());
            if let (Some(since), Some(act)) = (since, &activity) {
                if act < since {
                    return false;
                }
            }
            if let (Some(until), Some(act)) = (until, &activity) {
                if act > until {
                    return false;
                }
            }
            true
        })
        .filter_map(|session| {
            session
                .get("session_id")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
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
    use serde_json::json;

    #[test]
    fn command_helper_coverage_estimate_tokens_rounds_up_word_count() {
        assert_eq!(estimate_tokens("one two three"), 4);
    }

    #[test]
    fn command_helper_coverage_synthesize_condensed_text_filters_and_stops_at_budget() {
        let entries = vec![
            json!({"role": "user", "verdict": "allowed", "content": "alpha beta"}),
            json!({"role": "assistant", "verdict": "blocked", "content": "should skip"}),
            json!({"role": "user", "verdict": "allowed", "content": ""}),
            json!({"role": "assistant", "verdict": "allowed", "content": "gamma delta epsilon"}),
        ];

        let text = synthesize_condensed_text(&entries, true, false, 5);
        assert_eq!(text, "user: alpha beta\n");
    }

    #[test]
    fn command_helper_coverage_synthesize_condensed_text_can_include_blocked_entries() {
        let entries = vec![
            json!({"role": "user", "verdict": "blocked", "content": "blocked content"}),
            json!({"role": "assistant", "verdict": "allowed", "content": "allowed content"}),
        ];

        let text = synthesize_condensed_text(&entries, false, true, 50);
        assert!(text.contains("user: blocked content"));
        assert!(text.contains("assistant: allowed content"));
    }

    #[test]
    fn command_helper_coverage_parse_rfc3339_rejects_invalid_timestamp() {
        assert!(parse_rfc3339("not-a-timestamp").is_err());
    }

    #[test]
    fn command_helper_coverage_build_sessions_path_includes_scope_team_and_agent() {
        assert_eq!(
            build_sessions_path(Some("team"), Some("team alpha"), Some("agent/beta")),
            "/v1/history/sessions?scope=team&team_id=team%20alpha&agent_id=agent%2Fbeta"
        );
    }

    #[test]
    fn command_helper_coverage_matching_session_ids_from_value_applies_window() {
        let since = parse_rfc3339("2025-01-10T00:00:00Z").unwrap();
        let until = parse_rfc3339("2025-01-20T00:00:00Z").unwrap();
        let value = json!({
            "sessions": [
                {"session_id": "sess-before", "last_activity_at": "2025-01-09T23:00:00Z"},
                {"session_id": "sess-match", "last_activity_at": "2025-01-15T12:00:00Z"},
                {"session_id": "sess-after", "last_activity_at": "2025-01-21T12:00:00Z"},
                {"last_activity_at": "2025-01-15T12:00:00Z"}
            ]
        });

        assert_eq!(
            matching_session_ids_from_value(&value, Some(&since), Some(&until)),
            vec!["sess-match".to_string()]
        );
    }

    #[test]
    fn command_helper_coverage_matching_session_ids_keeps_missing_timestamps() {
        let since = parse_rfc3339("2025-01-10T00:00:00Z").unwrap();
        let value = json!({
            "sessions": [
                {"session_id": "sess-missing"},
                {"session_id": "sess-valid", "last_activity_at": "2025-01-15T12:00:00Z"}
            ]
        });

        assert_eq!(
            matching_session_ids_from_value(&value, Some(&since), None),
            vec!["sess-missing".to_string(), "sess-valid".to_string()]
        );
    }

    #[test]
    fn synthesize_condensed_text_skips_blocked_when_not_include_blocked() {
        let entries = vec![
            json!({"role": "user", "verdict": "blocked", "content": "blocked msg"}),
            json!({"role": "assistant", "verdict": "unknown", "content": "unknown msg"}),
        ];
        let text = synthesize_condensed_text(&entries, false, false, 100);
        assert!(!text.contains("blocked msg"));
        assert!(text.contains("unknown msg"));
    }

    #[test]
    fn synthesize_condensed_text_includes_unknown_verdict_when_not_allowed_only() {
        let entries = vec![
            json!({"role": "system", "content": "system instructions"}),
            json!({"role": "user", "content": "user request"}),
        ];
        let text = synthesize_condensed_text(&entries, false, false, 100);
        assert!(text.contains("system: system instructions"));
        assert!(text.contains("user: user request"));
    }

    #[test]
    fn synthesize_condensed_text_skips_empty_content() {
        let entries = vec![
            json!({"role": "user", "verdict": "allowed", "content": ""}),
            json!({"role": "user", "verdict": "allowed", "content": "   "}),
            json!({"role": "user", "verdict": "allowed", "content": "real content"}),
        ];
        let text = synthesize_condensed_text(&entries, false, false, 100);
        assert_eq!(text, "user: real content\n");
    }

    #[test]
    fn synthesize_condensed_text_respects_max_chars_boundary() {
        let entries = vec![
            json!({"role": "user", "verdict": "allowed", "content": "short"}),
            json!({"role": "assistant", "verdict": "allowed", "content": "this is a much longer response that should exceed the budget"}),
        ];
        let text = synthesize_condensed_text(&entries, false, false, 5);
        assert!(text.contains("user: short"));
        assert!(!text.contains("much longer"));
    }

    #[test]
    fn matching_session_ids_from_value_no_filters() {
        let value = json!({
            "sessions": [
                {"session_id": "s1", "last_activity_at": "2025-01-01T00:00:00Z"},
                {"session_id": "s2", "last_activity_at": "2025-06-01T00:00:00Z"}
            ]
        });
        let ids = matching_session_ids_from_value(&value, None, None);
        assert_eq!(ids, vec!["s1".to_string(), "s2".to_string()]);
    }

    #[test]
    fn matching_session_ids_from_value_empty_sessions() {
        let value = json!({"sessions": []});
        let ids = matching_session_ids_from_value(&value, None, None);
        assert!(ids.is_empty());
    }

    #[test]
    fn matching_session_ids_from_value_missing_key() {
        let value = json!({});
        let ids = matching_session_ids_from_value(&value, None, None);
        assert!(ids.is_empty());
    }

    #[test]
    fn estimate_tokens_basic() {
        assert_eq!(estimate_tokens(""), 0);
        assert_eq!(estimate_tokens("hello"), 2);
        assert_eq!(estimate_tokens("one two three"), 4);
    }

    #[test]
    fn build_sessions_path_no_filters() {
        assert_eq!(
            build_sessions_path(None, None, None),
            "/v1/history/sessions"
        );
    }

    #[test]
    fn build_sessions_path_scope_only() {
        assert_eq!(
            build_sessions_path(Some("org"), None, None),
            "/v1/history/sessions?scope=org"
        );
    }
}
