// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan history get-session` — fetch a single History session and optionally
//! its entries.
//!
//! # Module wiring
//! Add `pub(crate) mod history_get_session;` to `cli/src/commands/mod.rs` to
//! activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct HistoryGetSessionArgs {
    /// History session id.
    #[arg(long)]
    pub(crate) session_id: String,

    /// Include entries in the response.
    #[arg(long)]
    pub(crate) include_entries: bool,

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
pub(crate) async fn run_async(args: HistoryGetSessionArgs) -> Result<(), CliError> {
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

    let session_path = format!("/v1/history/sessions/{}", args.session_id);
    let mut value = client.get_json_value(&session_path).await?;

    if args.include_entries {
        let entries_path = format!("/v1/history/sessions/{}/entries", args.session_id);
        match client.get_json_value(&entries_path).await {
            Ok(entries) => {
                value = attach_entries(value, entries);
            }
            Err(e) => {
                eprintln!("warning: could not fetch entries: {e}");
            }
        }
    }

    if args.json {
        return print_json(&value);
    }

    println!("{}", session_summary_text(&value));

    Ok(())
}

fn attach_entries(mut value: serde_json::Value, entries: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = value.as_object_mut() {
        obj.insert("entries".to_string(), entries);
    }
    value
}

fn session_summary_text(value: &serde_json::Value) -> String {
    let session = value.get("session").unwrap_or(value);
    let id = session
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or("-");
    let scope = session.get("scope").and_then(|v| v.as_str()).unwrap_or("-");
    let entries = session
        .get("entry_count")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let allowed = session
        .get("allowed_entry_count")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let blocked = session
        .get("blocked_entry_count")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let started = session
        .get("started_at")
        .and_then(|v| v.as_str())
        .unwrap_or("-");

    format!(
        "session_id:       {id}\nscope:            {scope}\nstarted_at:       {started}\nentry_count:      {entries}\nallowed:          {allowed}\nblocked:          {blocked}"
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
    use serde_json::json;

    #[test]
    fn attach_entries_inserts_payload_on_object_values() {
        let value = json!({"session": {"session_id": "sess-1"}});
        let merged = attach_entries(value, json!({"entries": [{"id": "entry-1"}]}));

        assert_eq!(merged["entries"]["entries"][0]["id"], "entry-1");
    }

    #[test]
    fn attach_entries_ignores_non_object_values() {
        let merged = attach_entries(json!(["not", "an", "object"]), json!({"entries": []}));
        assert_eq!(merged, json!(["not", "an", "object"]));
    }

    #[test]
    fn session_summary_text_prefers_nested_session_payload() {
        let value = json!({
            "session": {
                "session_id": "sess-1",
                "scope": "team",
                "entry_count": 7,
                "allowed_entry_count": 5,
                "blocked_entry_count": 2,
                "started_at": "2025-01-15T11:00:00Z"
            }
        });

        assert_eq!(
            session_summary_text(&value),
            "session_id:       sess-1\nscope:            team\nstarted_at:       2025-01-15T11:00:00Z\nentry_count:      7\nallowed:          5\nblocked:          2"
        );
    }

    #[test]
    fn session_summary_text_falls_back_to_top_level_and_defaults() {
        let value = json!({
            "session_id": "sess-top",
            "scope": "org"
        });

        assert_eq!(
            session_summary_text(&value),
            "session_id:       sess-top\nscope:            org\nstarted_at:       -\nentry_count:      0\nallowed:          0\nblocked:          0"
        );
    }

    #[test]
    fn session_summary_text_all_defaults() {
        let value = json!({});
        let text = session_summary_text(&value);
        assert!(text.contains("session_id:       -"));
        assert!(text.contains("scope:            -"));
        assert!(text.contains("started_at:       -"));
        assert!(text.contains("entry_count:      0"));
        assert!(text.contains("allowed:          0"));
        assert!(text.contains("blocked:          0"));
    }

    #[test]
    fn attach_entries_adds_under_entries_key() {
        let value = json!({"session_id": "s1"});
        let entries = json!({"data": [1, 2, 3]});
        let merged = attach_entries(value, entries.clone());
        assert_eq!(merged["entries"], entries);
        assert_eq!(merged["session_id"], "s1");
    }

    #[test]
    fn get_session_path_formatting() {
        let sid = "my-session-123";
        let encoded = urlencoding::encode(sid);
        let path = format!("/v1/history/sessions/{encoded}");
        assert_eq!(path, "/v1/history/sessions/my-session-123");
    }

    #[test]
    fn get_session_path_encodes_special_chars() {
        let sid = "sess/with space";
        let encoded = urlencoding::encode(sid);
        let path = format!("/v1/history/sessions/{encoded}");
        assert_eq!(path, "/v1/history/sessions/sess%2Fwith%20space");
    }
}
