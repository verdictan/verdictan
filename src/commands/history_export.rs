// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan history export <session_id>` — export a session's conversation to
//! markdown, JSON, or plain text.
//!
//! Calls `GET /v1/history/sessions/{id}` for metadata and
//! `GET /v1/history/sessions/{id}/entries` for all entries, then formats
//! according to `--format`.

use std::{collections::HashSet, path::PathBuf};

use clap::Args;
use serde_json::Value;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;

const HISTORY_EXPORT_PAGE_SIZE: usize = 500;

#[derive(Debug, Clone, clap::ValueEnum)]
pub(crate) enum ExportFormat {
    Markdown,
    Json,
    Txt,
}

#[derive(Debug, Args)]
pub(crate) struct HistoryExportArgs {
    /// Session id to export.
    pub(crate) session_id: String,

    /// Output format.
    #[arg(long, value_enum, default_value = "markdown")]
    pub(crate) format: ExportFormat,

    /// Write to a file, not stdout.
    #[arg(long)]
    pub(crate) output: Option<PathBuf>,

    /// Optional config file path (YAML).
    #[arg(long)]
    pub(crate) config: Option<PathBuf>,

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
pub(crate) async fn run_async(args: HistoryExportArgs) -> Result<(), CliError> {
    let client = build_client(
        args.api_url,
        args.api_token,
        args.config,
        args.profile,
        args.region,
    )?;

    // Fetch session metadata.
    let session_path = format!(
        "/v1/history/sessions/{}",
        urlencoding::encode(&args.session_id)
    );
    let session_value = client.get_json_value(&session_path).await?;
    let session = session_value
        .get("session")
        .filter(|value| value.is_object())
        .ok_or_else(|| {
            CliError::internal("history session response is malformed: expected a session object")
        })?;
    let expected_entry_count = session
        .get("entry_count")
        .and_then(Value::as_i64)
        .filter(|count| *count >= 0)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(|| {
            CliError::internal(
                "history session response is malformed: expected a non-negative entry_count",
            )
        })?;

    // Fetch every entry page before formatting or creating the output file.
    let entries = fetch_all_entries(&client, &args.session_id, expected_entry_count).await?;

    let output_text = match args.format {
        ExportFormat::Markdown => format_markdown(session, &entries),
        ExportFormat::Json => format_json(session, &entries)?,
        ExportFormat::Txt => format_txt(&entries),
    };

    match args.output {
        Some(path) => {
            std::fs::write(&path, &output_text).map_err(|e| {
                CliError::user(format!("failed to write to {}: {e}", path.display()))
            })?;
            eprintln!("exported to {}", path.display());
        }
        None => {
            print!("{output_text}");
        }
    }

    Ok(())
}

async fn fetch_all_entries(
    client: &AsyncApiClient,
    session_id: &str,
    expected_entry_count: usize,
) -> Result<Vec<Value>, CliError> {
    let encoded_session_id = urlencoding::encode(session_id);
    let mut entries = Vec::new();
    let mut seen_entry_ids = HashSet::new();
    let mut last_request_index = None;
    let mut offset = 0usize;

    loop {
        let entries_path = format!(
            "/v1/history/sessions/{encoded_session_id}/entries?limit={HISTORY_EXPORT_PAGE_SIZE}&offset={offset}"
        );
        let page_value = client.get_json_value(&entries_path).await?;
        let page = page_value
            .get("entries")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| {
                CliError::internal(format!(
                    "history entries response at offset {offset} is malformed: expected an entries array"
                ))
            })?;
        let page_len = page.len();

        if page_len > HISTORY_EXPORT_PAGE_SIZE {
            return Err(CliError::internal(format!(
                "history entries response at offset {offset} is malformed: returned {page_len} entries for a {HISTORY_EXPORT_PAGE_SIZE}-entry page"
            )));
        }

        append_validated_page(
            &mut entries,
            &mut seen_entry_ids,
            &mut last_request_index,
            page,
            offset,
        )?;

        if page_len < HISTORY_EXPORT_PAGE_SIZE {
            if entries.len() < expected_entry_count {
                return Err(CliError::internal(format!(
                    "history entries pagination ended after {} entries, but the session reports {expected_entry_count}; refusing an incomplete export",
                    entries.len()
                )));
            }
            break;
        }

        offset = offset
            .checked_add(page_len)
            .ok_or_else(|| CliError::internal("history entries pagination offset overflowed"))?;
    }

    Ok(entries)
}

fn append_validated_page(
    entries: &mut Vec<Value>,
    seen_entry_ids: &mut HashSet<String>,
    last_request_index: &mut Option<i64>,
    page: Vec<Value>,
    offset: usize,
) -> Result<(), CliError> {
    for (position, entry) in page.into_iter().enumerate() {
        let entry_object = entry.as_object().ok_or_else(|| {
            CliError::internal(format!(
                "history entries response at offset {offset} is malformed: entry {position} is not an object"
            ))
        })?;
        let entry_id = entry_object
            .get("entry_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CliError::internal(format!(
                    "history entries response at offset {offset} is malformed: entry {position} has no entry_id"
                ))
            })?;
        let request_index = entry_object
            .get("request_index")
            .and_then(Value::as_i64)
            .ok_or_else(|| {
                CliError::internal(format!(
                    "history entries response at offset {offset} is malformed: entry {position} has no integer request_index"
                ))
            })?;

        if !seen_entry_ids.insert(entry_id.to_string()) {
            return Err(CliError::internal(format!(
                "history entries pagination repeated entry_id {entry_id}; refusing an incomplete export"
            )));
        }
        if last_request_index.is_some_and(|previous| request_index <= previous) {
            return Err(CliError::internal(format!(
                "history entries pagination is not in strictly increasing request_index order at entry_id {entry_id}; refusing an incomplete export"
            )));
        }

        *last_request_index = Some(request_index);
        entries.push(entry);
    }

    Ok(())
}

fn format_markdown(session: &Value, entries: &[Value]) -> String {
    let mut out = String::new();

    // YAML frontmatter with session metadata.
    out.push_str("---\n");
    if let Some(id) = session.get("session_id").and_then(|v| v.as_str()) {
        out.push_str(&format!("session_id: {id}\n"));
    }
    if let Some(scope) = session.get("scope").and_then(|v| v.as_str()) {
        out.push_str(&format!("scope: {scope}\n"));
    }
    if let Some(started) = session.get("started_at").and_then(|v| v.as_str()) {
        out.push_str(&format!("started_at: {started}\n"));
    }
    if let Some(count) = session.get("entry_count").and_then(|v| v.as_i64()) {
        out.push_str(&format!("entry_count: {count}\n"));
    }
    if let Some(tags) = session.get("tags").and_then(|v| v.as_array()) {
        let tag_strs: Vec<&str> = tags.iter().filter_map(|t| t.as_str()).collect();
        if !tag_strs.is_empty() {
            out.push_str(&format!("tags: [{}]\n", tag_strs.join(", ")));
        }
    }
    out.push_str("---\n\n");

    for entry in entries {
        let role = extract_role(entry);
        let content = extract_content(entry);
        out.push_str(&format!("## {role}\n\n{content}\n\n"));
    }

    out
}

fn format_json(session: &Value, entries: &[Value]) -> Result<String, CliError> {
    let output = serde_json::json!({
        "session": session,
        "entries": entries,
    });
    serde_json::to_string_pretty(&output)
        .map_err(|e| CliError::internal(format!("failed to serialize JSON: {e}")))
}

fn format_txt(entries: &[Value]) -> String {
    let mut out = String::new();
    for entry in entries {
        let role = extract_role(entry);
        let content = extract_content(entry);
        out.push_str(&format!("[{role}]: {content}\n\n"));
    }
    out
}

fn extract_role(entry: &Value) -> String {
    // Try request_payload.messages[last].role or entry_kind.
    if let Some(messages) = entry
        .get("request_payload")
        .and_then(|p| p.get("messages"))
        .and_then(|m| m.as_array())
    {
        if let Some(last) = messages.last() {
            if let Some(role) = last.get("role").and_then(|r| r.as_str()) {
                return role.to_string();
            }
        }
    }
    entry
        .get("entry_kind")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string()
}

fn extract_content(entry: &Value) -> String {
    // Try response content first, then request messages.
    if let Some(content) = entry
        .get("response_payload")
        .and_then(|p| p.get("choices"))
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
    {
        return content.to_string();
    }
    if let Some(messages) = entry
        .get("request_payload")
        .and_then(|p| p.get("messages"))
        .and_then(|m| m.as_array())
    {
        if let Some(last) = messages.last() {
            if let Some(content) = last.get("content").and_then(|c| c.as_str()) {
                return content.to_string();
            }
        }
    }
    entry
        .get("content")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn build_client(
    api_url: Option<String>,
    api_token: Option<String>,
    config_path: Option<PathBuf>,
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
    fn format_markdown_renders_frontmatter_and_entries() {
        let session = json!({
            "session_id": "sess-export",
            "scope": "team",
            "started_at": "2025-01-15T10:00:00Z",
            "entry_count": 2,
            "tags": ["incident", "ops"]
        });
        let entries = vec![
            json!({
                "request_payload": {
                    "messages": [{"role": "user", "content": "what happened?"}]
                }
            }),
            json!({
                "entry_kind": "assistant",
                "response_payload": {
                    "choices": [{
                        "message": {
                            "role": "assistant",
                            "content": "the system recovered"
                        }
                    }]
                }
            }),
        ];

        let markdown = format_markdown(&session, &entries);

        assert!(markdown.contains("session_id: sess-export"));
        assert!(markdown.contains("tags: [incident, ops]"));
        assert!(markdown.contains("## user\n\nwhat happened?"));
        assert!(markdown.contains("## assistant\n\nthe system recovered"));
    }

    #[test]
    fn format_json_wraps_session_and_entries() {
        let session = json!({"session_id": "sess-1"});
        let entries = vec![json!({"entry_kind": "user", "content": "hello"})];

        let rendered = format_json(&session, &entries).expect("json formatting");
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");

        assert_eq!(parsed["session"]["session_id"], "sess-1");
        assert_eq!(parsed["entries"][0]["content"], "hello");
    }

    #[test]
    fn format_txt_uses_extracted_role_and_content() {
        let entries = vec![
            json!({
                "request_payload": {
                    "messages": [{"role": "user", "content": "user asks"}]
                }
            }),
            json!({
                "entry_kind": "assistant",
                "response_payload": {
                    "choices": [{
                        "message": {
                            "role": "assistant",
                            "content": "assistant answers"
                        }
                    }]
                }
            }),
        ];

        let text = format_txt(&entries);

        assert!(text.contains("[user]: user asks"));
        assert!(text.contains("[assistant]: assistant answers"));
    }

    #[test]
    fn extract_role_prefers_last_request_message_and_falls_back_to_entry_kind() {
        let from_request = json!({
            "entry_kind": "fallback-kind",
            "request_payload": {
                "messages": [
                    {"role": "system", "content": "setup"},
                    {"role": "user", "content": "latest role wins"}
                ]
            }
        });
        let from_kind = json!({"entry_kind": "assistant"});

        assert_eq!(extract_role(&from_request), "user");
        assert_eq!(extract_role(&from_kind), "assistant");
    }

    #[test]
    fn extract_content_prefers_response_then_request_then_content() {
        let from_response = json!({
            "request_payload": {
                "messages": [{"role": "user", "content": "request text"}]
            },
            "response_payload": {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "response text"
                    }
                }]
            },
            "content": "stored text"
        });
        let from_request = json!({
            "request_payload": {
                "messages": [{"role": "user", "content": "request only"}]
            }
        });
        let from_content = json!({"content": "content only"});

        assert_eq!(extract_content(&from_response), "response text");
        assert_eq!(extract_content(&from_request), "request only");
        assert_eq!(extract_content(&from_content), "content only");
    }

    #[test]
    fn append_validated_page_rejects_duplicate_entry_ids_across_pages() {
        let mut entries = Vec::new();
        let mut seen_entry_ids = HashSet::new();
        let mut last_request_index = None;
        append_validated_page(
            &mut entries,
            &mut seen_entry_ids,
            &mut last_request_index,
            vec![json!({"entry_id": "entry-1", "request_index": 1})],
            0,
        )
        .expect("first page");

        let error = append_validated_page(
            &mut entries,
            &mut seen_entry_ids,
            &mut last_request_index,
            vec![json!({"entry_id": "entry-1", "request_index": 2})],
            500,
        )
        .expect_err("duplicate entry ID must fail");

        assert!(error.to_string().contains("repeated entry_id entry-1"));
    }

    #[test]
    fn append_validated_page_rejects_non_increasing_request_indexes() {
        let mut entries = Vec::new();
        let mut seen_entry_ids = HashSet::new();
        let mut last_request_index = None;
        append_validated_page(
            &mut entries,
            &mut seen_entry_ids,
            &mut last_request_index,
            vec![json!({"entry_id": "entry-2", "request_index": 2})],
            0,
        )
        .expect("first page");

        let error = append_validated_page(
            &mut entries,
            &mut seen_entry_ids,
            &mut last_request_index,
            vec![json!({"entry_id": "entry-3", "request_index": 1})],
            500,
        )
        .expect_err("out-of-order request index must fail");

        assert!(error
            .to_string()
            .contains("not in strictly increasing request_index order"));
    }

    #[test]
    fn append_validated_page_rejects_malformed_entries() {
        let mut entries = Vec::new();
        let mut seen_entry_ids = HashSet::new();
        let mut last_request_index = None;

        let error = append_validated_page(
            &mut entries,
            &mut seen_entry_ids,
            &mut last_request_index,
            vec![json!({"entry_id": "entry-without-index"})],
            0,
        )
        .expect_err("missing request index must fail");

        assert!(error.to_string().contains("no integer request_index"));
    }
}
