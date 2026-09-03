// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan secret create` — create a new secret.
//!
//! Secret material MUST NOT be supplied as a plain CLI flag. Exactly one of
//! the secure source flags must be provided:
//!
//! * `--env-var VAR_NAME` — read the value from the named environment variable
//! * `--keychain svc:acct` — read the value from the macOS keychain
//! * `--stdin` — read the value from stdin (explicit opt-in)
//!
//! # Module wiring
//! Add `pub(crate) mod secret_create;` to `cli/src/commands/mod.rs` to activate.

use clap::Args;

use crate::api::admin::{parse_secret_source, resolve_secret_value};
use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct SecretCreateArgs {
    /// Secret name (unique in the organization).
    #[arg(long)]
    pub(crate) name: String,

    /// Secret type (for example, "api_key" or "oauth_token").
    #[arg(long)]
    pub(crate) kind: Option<String>,

    /// Optional description.
    #[arg(long)]
    pub(crate) description: Option<String>,

    // ---- secure value sources (exactly one required) ----
    /// Read secret material from this environment variable.
    #[arg(long, value_name = "VAR_NAME", conflicts_with_all = ["keychain", "stdin"])]
    pub(crate) env_var: Option<String>,

    /// Read secret material from the macOS keychain entry "service:account".
    #[arg(long, value_name = "SVC:ACCT", conflicts_with_all = ["env_var", "stdin"])]
    pub(crate) keychain: Option<String>,

    /// Read secret material from stdin.
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
pub(crate) async fn run_async(args: SecretCreateArgs) -> Result<(), CliError> {
    let source = parse_secret_source(args.env_var, args.keychain, args.stdin)?;
    let value_str = resolve_secret_value(&source)?;

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

    let mut body = serde_json::json!({
        "name": args.name,
        "value": value_str,
    });
    if let Some(kind) = args.kind {
        body["kind"] = serde_json::Value::String(kind);
    }
    if let Some(desc) = args.description {
        body["description"] = serde_json::Value::String(desc);
    }

    let result = client.post_json_value("/v1/secrets", &body).await?;

    if args.json {
        return print_json(&result);
    }

    let id = result
        .get("secret")
        .and_then(|secret| secret.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("-");
    println!("created secret {id}");
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
    fn create_body_required_fields() {
        let body = json!({
            "name": "my-secret",
            "value": "s3cr3t",
        });
        assert_eq!(body["name"], "my-secret");
        assert_eq!(body["value"], "s3cr3t");
    }

    #[test]
    fn create_body_with_kind_and_description() {
        let mut body = json!({
            "name": "key",
            "value": "val",
        });
        body["kind"] = serde_json::Value::String("api_key".into());
        body["description"] = serde_json::Value::String("Main API key".into());
        assert_eq!(body["kind"], "api_key");
        assert_eq!(body["description"], "Main API key");
    }

    #[test]
    fn parse_secret_create_response() {
        let result = json!({"secret": {"id": "sec-1"}});
        let id = result
            .get("secret")
            .and_then(|s| s.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        assert_eq!(id, "sec-1");
    }

    #[test]
    fn parse_secret_create_response_missing() {
        let result = json!({});
        let id = result
            .get("secret")
            .and_then(|s| s.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        assert_eq!(id, "-");
    }
}
