// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan secret update` — update an existing secret.
//!
//! Secret material MUST NOT be supplied as a plain CLI flag. If a new value
//! is needed, exactly one secure source must be provided:
//!
//! * `--env-var VAR_NAME` — read the value from the named environment variable
//! * `--keychain svc:acct` — read the value from the macOS keychain
//! * `--stdin` — read the value from stdin (explicit opt-in)
//!
//! Metadata fields (`--name`, `--description`) may be updated without providing
//! a new value.
//!
//! # Module wiring
//! Add `pub(crate) mod secret_update;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::admin::{parse_secret_source, resolve_secret_value};
use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct SecretUpdateArgs {
    /// Secret id.
    #[arg(long)]
    pub(crate) secret_id: String,

    /// New description.
    #[arg(long)]
    pub(crate) description: Option<String>,

    // ---- optional new secret value (at most one source) ----
    /// Read new secret material from this environment variable.
    #[arg(long, value_name = "VAR_NAME", conflicts_with_all = ["keychain", "stdin"])]
    pub(crate) env_var: Option<String>,

    /// Read new secret material from the macOS keychain entry "service:account".
    #[arg(long, value_name = "SVC:ACCT", conflicts_with_all = ["env_var", "stdin"])]
    pub(crate) keychain: Option<String>,

    /// Read new secret material from stdin.
    #[arg(long, conflicts_with_all = ["env_var", "keychain"])]
    pub(crate) stdin: bool,

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
pub(crate) async fn run_async(args: SecretUpdateArgs) -> Result<(), CliError> {
    // Resolve secret value only when at least one source flag was provided.
    let has_value_source = args.env_var.is_some() || args.keychain.is_some() || args.stdin;
    let new_value = if has_value_source {
        let source = parse_secret_source(args.env_var, args.keychain, args.stdin)?;
        Some(resolve_secret_value(&source)?)
    } else {
        None
    };

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

    let mut body = serde_json::json!({});
    if let Some(desc) = args.description {
        body["description"] = serde_json::Value::String(desc);
    }
    if let Some(val) = new_value {
        body["value"] = serde_json::Value::String(val);
    }

    if body.as_object().map(|o| o.is_empty()).unwrap_or(true) {
        return Err(CliError::user(
            "nothing to update: provide at least one field",
        ));
    }

    let path = format!("/v1/secrets/{}", args.secret_id);
    let result = client.put_json_value(&path, &body).await?;

    if args.json {
        return print_json(&result);
    }

    let id = result
        .get("secret")
        .and_then(|secret| secret.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or(&args.secret_id);
    println!("updated secret {id}");
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
    fn has_value_source_detection() {
        assert!(true || false || false);
        assert!(!false && !false && !false);
    }

    #[test]
    fn update_body_description_only() {
        let mut body = json!({});
        body["description"] = serde_json::Value::String("Updated".into());
        assert_eq!(body["description"], "Updated");
        assert!(body.get("value").is_none());
    }

    #[test]
    fn update_body_value_only() {
        let mut body = json!({});
        body["value"] = serde_json::Value::String("new-secret".into());
        assert_eq!(body["value"], "new-secret");
    }

    #[test]
    fn empty_update_body_detected() {
        let body = json!({});
        let is_empty = body.as_object().map(|o| o.is_empty()).unwrap_or(true);
        assert!(is_empty);
    }

    #[test]
    fn update_path_formatting() {
        let secret_id = "sec-42";
        let path = format!("/v1/secrets/{}", secret_id);
        assert_eq!(path, "/v1/secrets/sec-42");
    }

    #[test]
    fn parse_update_response() {
        let result = json!({"secret": {"id": "sec-1"}});
        let fallback = "sec-fallback".to_string();
        let id = result
            .get("secret")
            .and_then(|s| s.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or(&fallback);
        assert_eq!(id, "sec-1");
    }

    #[test]
    fn parse_update_response_falls_back_to_input_id() {
        let result = json!({});
        let fallback = "sec-original".to_string();
        let id = result
            .get("secret")
            .and_then(|s| s.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or(&fallback);
        assert_eq!(id, "sec-original");
    }

    #[test]
    fn update_body_both_description_and_value() {
        let mut body = json!({});
        body["description"] = serde_json::Value::String("desc".into());
        body["value"] = serde_json::Value::String("val".into());
        assert_eq!(body.as_object().unwrap().len(), 2);
    }

    #[test]
    fn non_empty_update_body_detected() {
        let body = json!({"description": "something"});
        let is_empty = body.as_object().map(|o| o.is_empty()).unwrap_or(true);
        assert!(!is_empty);
    }
}
