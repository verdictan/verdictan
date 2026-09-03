// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan secret list` — list secrets in the organisation.
//!
//! # Module wiring
//! Add `pub(crate) mod secret_list;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct SecretListArgs {
    /// Filter by secret type (for example, "api_key" or "oauth_token").
    #[arg(long)]
    pub(crate) kind: Option<String>,

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
pub(crate) async fn run_async(args: SecretListArgs) -> Result<(), CliError> {
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

    let mut query = Vec::new();
    if let Some(kind) = &args.kind {
        query.push(format!("kind={}", urlencoding::encode(kind)));
    }

    let path = if query.is_empty() {
        "/v1/secrets".to_string()
    } else {
        format!("/v1/secrets?{}", query.join("&"))
    };

    let value = client.get_json_value(&path).await?;

    if args.json {
        return print_json(&value);
    }

    let secrets = value
        .get("secrets")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    if secrets.is_empty() {
        println!("no secrets");
        return Ok(());
    }

    for s in &secrets {
        let id = s.get("id").and_then(|v| v.as_str()).unwrap_or("-");
        let name = s.get("name").and_then(|v| v.as_str()).unwrap_or("-");
        let source_kind = s.get("source_kind").and_then(|v| v.as_str()).unwrap_or("-");
        println!("{id}  {name}  {source_kind}");
    }

    Ok(())
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

    #[test]
    fn query_string_with_kind_filter() {
        let kind = Some("api_key".to_string());
        let mut query = Vec::new();
        if let Some(k) = &kind {
            query.push(format!("kind={}", urlencoding::encode(k)));
        }
        let path = if query.is_empty() {
            "/v1/secrets".to_string()
        } else {
            format!("/v1/secrets?{}", query.join("&"))
        };
        assert_eq!(path, "/v1/secrets?kind=api_key");
    }

    #[test]
    fn query_string_without_filter() {
        let kind: Option<String> = None;
        let mut query = Vec::new();
        if let Some(k) = &kind {
            query.push(format!("kind={}", urlencoding::encode(k)));
        }
        let path = if query.is_empty() {
            "/v1/secrets".to_string()
        } else {
            format!("/v1/secrets?{}", query.join("&"))
        };
        assert_eq!(path, "/v1/secrets");
    }

    #[test]
    fn query_string_encodes_special_chars() {
        let kind = Some("foo bar".to_string());
        let encoded = urlencoding::encode(kind.as_ref().unwrap());
        assert_eq!(encoded, "foo%20bar");
    }

    #[test]
    fn parse_secrets_response() {
        let value = json!({"secrets": [
            {"id": "s-1", "name": "key1", "source_kind": "api_key"}
        ]});
        let secrets = value
            .get("secrets")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        assert_eq!(secrets.len(), 1);
    }

    #[test]
    fn secret_row_defaults() {
        let s = json!({});
        let id = s.get("id").and_then(|v| v.as_str()).unwrap_or("-");
        let name = s.get("name").and_then(|v| v.as_str()).unwrap_or("-");
        let sk = s.get("source_kind").and_then(|v| v.as_str()).unwrap_or("-");
        assert_eq!(id, "-");
        assert_eq!(name, "-");
        assert_eq!(sk, "-");
    }
}
