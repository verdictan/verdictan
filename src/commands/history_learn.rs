// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan history learn` — trigger server-side history learning for a session or
//! preview the source entries that would be used.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct HistoryLearnArgs {
    /// Bind the learn request to a specified session id.
    #[arg(long = "bind-to-session")]
    pub(crate) bind_to_session: Option<String>,

    /// Scope filter when `--bind-to-session` is not set.
    #[arg(long, value_parser = ["user", "team", "org"])]
    pub(crate) scope: Option<String>,

    /// Team id filter for session discovery.
    #[arg(long)]
    pub(crate) team_id: Option<String>,

    /// Agent id filter for session discovery.
    #[arg(long)]
    pub(crate) agent_id: Option<String>,

    /// Learning strategy.
    #[arg(long, default_value = "condense", value_parser = ["extract", "condense", "hybrid"])]
    pub(crate) strategy: String,

    /// Maximum number of prior sessions that the API can use as context.
    #[arg(long, default_value_t = 4)]
    pub(crate) previous_sessions_max: u32,

    /// Target token budget for the learned artifact.
    #[arg(long, default_value_t = 1200)]
    pub(crate) target_max_tokens: u32,

    /// Fetch the source entries and print a preview without posting `/learn`.
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

pub(crate) async fn run_async(args: HistoryLearnArgs) -> Result<(), CliError> {
    let client = build_client(
        args.api_url,
        args.api_token,
        args.config,
        args.profile,
        args.region,
    )?;

    let session_id = match args.bind_to_session {
        Some(session_id) => session_id,
        None => {
            resolve_most_recent_session_id(
                &client,
                args.scope.as_deref(),
                args.team_id.as_deref(),
                args.agent_id.as_deref(),
            )
            .await?
        }
    };

    let encoded_session_id = urlencoding::encode(&session_id);

    if args.dry_run {
        let path = format!("/v1/history/sessions/{encoded_session_id}/entries");
        let response = client.get_json_value(&path).await?;
        let entries = response
            .get("entries")
            .and_then(|value| value.as_array())
            .cloned()
            .unwrap_or_default();

        let preview = serde_json::json!({
            "dry_run": true,
            "session_id": session_id,
            "strategy": args.strategy,
            "previous_sessions_max": args.previous_sessions_max,
            "target_max_tokens": args.target_max_tokens,
            "entries_fetched": entries.len(),
            "entries": entries,
        });

        if args.json {
            return print_json(&preview);
        }

        println!("dry-run: history learn");
        println!("session: {session_id}");
        println!("strategy: {}", args.strategy);
        println!("entries fetched: {}", preview["entries_fetched"]);
        return Ok(());
    }

    let path = format!("/v1/history/sessions/{encoded_session_id}/learn");
    let response = client
        .post_json_value(
            &path,
            &serde_json::json!({
                "strategy": args.strategy,
                "previous_sessions_max": args.previous_sessions_max,
                "target_max_tokens": args.target_max_tokens,
            }),
        )
        .await?;

    if args.json {
        return print_json(&response);
    }

    let status = response
        .get("condensation")
        .and_then(|value| value.get("status"))
        .and_then(|value| value.as_str())
        .unwrap_or("accepted");
    let condensation_id = response
        .get("condensation")
        .and_then(|value| value.get("id"))
        .and_then(|value| value.as_str())
        .unwrap_or("-");

    println!("history learn requested");
    println!("session: {session_id}");
    println!("condensation: {condensation_id}");
    println!("status: {status}");

    Ok(())
}

async fn resolve_most_recent_session_id(
    client: &AsyncApiClient,
    scope: Option<&str>,
    team_id: Option<&str>,
    agent_id: Option<&str>,
) -> Result<String, CliError> {
    let path = build_sessions_discovery_path(scope, team_id, agent_id);

    let response = client.get_json_value(&path).await?;
    let sessions = response
        .get("sessions")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();

    pick_most_recent_session(&sessions)
        .map(str::to_owned)
        .ok_or_else(|| CliError::user("no matching history sessions found"))
}

fn build_client(
    api_url: Option<String>,
    api_token: Option<String>,
    config_path: Option<std::path::PathBuf>,
    profile: String,
    region: Option<String>,
) -> Result<AsyncApiClient, CliError> {
    let inputs = ConfigInputs {
        api_url_flag: api_url,
        api_token_flag: api_token,
        config_path,
        profile_flag: Some(profile),
        region_flag: region,
    };
    let config = Config::resolve(inputs)?;
    let token = config.api_token.ok_or_else(|| {
        CliError::auth("missing api token (set VERDICTAN_API_TOKEN or run `verdictan auth login`)")
    })?;
    Ok(AsyncApiClient::new(config.api_url, token)?.with_region(config.region))
}

fn pick_most_recent_session(sessions: &[serde_json::Value]) -> Option<&str> {
    sessions
        .iter()
        .max_by_key(|session| {
            session
                .get("last_activity_at")
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .to_string()
        })
        .and_then(|session| session.get("session_id").and_then(|value| value.as_str()))
}

fn build_sessions_discovery_path(
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
    fn pick_most_recent_session_selects_latest_activity() {
        let sessions = vec![
            json!({"session_id": "old", "last_activity_at": "2024-01-01T00:00:00Z"}),
            json!({"session_id": "newest", "last_activity_at": "2024-06-15T12:00:00Z"}),
            json!({"session_id": "mid", "last_activity_at": "2024-03-10T06:00:00Z"}),
        ];
        assert_eq!(pick_most_recent_session(&sessions), Some("newest"));
    }

    #[test]
    fn pick_most_recent_session_returns_none_for_empty() {
        let sessions: Vec<serde_json::Value> = vec![];
        assert_eq!(pick_most_recent_session(&sessions), None);
    }

    #[test]
    fn pick_most_recent_session_handles_missing_timestamp() {
        let sessions = vec![
            json!({"session_id": "a"}),
            json!({"session_id": "b", "last_activity_at": "2024-01-01T00:00:00Z"}),
        ];
        assert_eq!(pick_most_recent_session(&sessions), Some("b"));
    }

    #[test]
    fn build_sessions_discovery_path_no_filters() {
        assert_eq!(
            build_sessions_discovery_path(None, None, None),
            "/v1/history/sessions"
        );
    }

    #[test]
    fn build_sessions_discovery_path_all_filters() {
        let path = build_sessions_discovery_path(Some("team"), Some("t-1"), Some("a-1"));
        assert!(path.starts_with("/v1/history/sessions?"));
        assert!(path.contains("scope=team"));
        assert!(path.contains("team_id=t-1"));
        assert!(path.contains("agent_id=a-1"));
    }

    #[test]
    fn build_sessions_discovery_path_encodes_special_chars() {
        let path = build_sessions_discovery_path(None, Some("team with spaces"), None);
        assert!(path.contains("team_id=team%20with%20spaces"));
    }

    #[test]
    fn session_id_encoding_in_learn_path() {
        let session_id = "session/with special&chars";
        let encoded = urlencoding::encode(session_id);
        assert!(!encoded.contains('/'));
        let path = format!("/v1/history/sessions/{encoded}/learn");
        assert!(path.contains("session%2Fwith%20special%26chars"));
    }
}
