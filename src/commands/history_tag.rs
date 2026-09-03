// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan history tag <session_id>` — manage tags on a history session.
//!
//! - `verdictan history tag <session_id>` — list current tags
//! - `verdictan history tag <session_id> --tag <name>` — add a tag
//! - `verdictan history tag <session_id> --remove <name>` — remove a tag

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct HistoryTagArgs {
    /// Session id.
    pub(crate) session_id: String,

    /// Tag name to add.
    #[arg(long)]
    pub(crate) tag: Option<String>,

    /// Tag name to remove.
    #[arg(long)]
    pub(crate) remove: Option<String>,

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
pub(crate) async fn run_async(args: HistoryTagArgs) -> Result<(), CliError> {
    let client = build_client(args.api_url, args.api_token, args.config, args.profile)?;

    let sid = urlencoding::encode(&args.session_id);

    if let Some(tag_name) = &args.tag {
        // Add tag.
        let path = format!("/v1/history/sessions/{sid}/tags");
        let body = serde_json::json!({ "tag": tag_name });
        let response = client.post_json_value(&path, &body).await?;
        return print_tags(&response, args.json);
    }

    if let Some(tag_name) = &args.remove {
        // Remove tag.
        let path = format!(
            "/v1/history/sessions/{sid}/tags/{}",
            urlencoding::encode(tag_name)
        );
        let response = client.delete_json_value(&path).await?;
        return print_tags(&response, args.json);
    }

    // List tags — fetch session and display tags array.
    let path = format!("/v1/history/sessions/{sid}");
    let response = client.get_json_value(&path).await?;
    print_tags(&response, args.json)
}

fn print_tags(value: &serde_json::Value, json_mode: bool) -> Result<(), CliError> {
    if json_mode {
        return print_json(value);
    }

    let tags = value
        .get("tags")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    if tags.is_empty() {
        println!("no tags");
    } else {
        let names: Vec<&str> = tags.iter().filter_map(|t| t.as_str()).collect();
        println!("tags: {}", names.join(", "));
    }

    Ok(())
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

    use super::print_tags;

    #[test]
    fn add_tag_path_formatting() {
        let sid = urlencoding::encode("sess-1");
        let path = format!("/v1/history/sessions/{sid}/tags");
        assert_eq!(path, "/v1/history/sessions/sess-1/tags");
    }

    #[test]
    fn remove_tag_path_formatting() {
        let sid = urlencoding::encode("sess-1");
        let tag_name = urlencoding::encode("important");
        let path = format!("/v1/history/sessions/{sid}/tags/{tag_name}");
        assert_eq!(path, "/v1/history/sessions/sess-1/tags/important");
    }

    #[test]
    fn add_tag_body_construction() {
        let tag_name = "flagged";
        let body = json!({ "tag": tag_name });
        assert_eq!(body["tag"], "flagged");
    }

    #[test]
    fn session_id_url_encoding() {
        let session_id = "sess with spaces";
        let encoded = urlencoding::encode(session_id);
        assert_eq!(encoded, "sess%20with%20spaces");
    }

    #[test]
    fn print_tags_empty_array() {
        let value = json!({"tags": []});
        let result = print_tags(&value, true);
        assert!(result.is_ok());
    }

    #[test]
    fn print_tags_missing_key() {
        let value = json!({});
        let tags = value
            .get("tags")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert!(tags.is_empty());
    }

    #[test]
    fn print_tags_with_values() {
        let value = json!({"tags": ["a", "b", "c"]});
        let tags = value.get("tags").and_then(|v| v.as_array()).unwrap();
        let names: Vec<&str> = tags.iter().filter_map(|t| t.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c"]);
    }
}
