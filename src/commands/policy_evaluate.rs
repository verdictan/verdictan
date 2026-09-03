// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use clap::Args;
use serde::de::DeserializeOwned;

use crate::commands::policy_common::{
    fetch_remote_policies, flatten_policy_statements, load_policy_specs_from_path,
    remote_policies_to_specs, resolve_client, PolicyApiArgs, PolicyRemoteSelectorArgs,
};
use crate::error::CliError;
use crate::output::json::print_json;

#[derive(Debug, Args)]
pub(crate) struct PolicyEvaluateArgs {
    /// Load policies from a local file (YAML or JSON).
    #[arg(long)]
    pub(crate) file: Option<std::path::PathBuf>,

    #[command(flatten)]
    pub(crate) selectors: PolicyRemoteSelectorArgs,

    /// Action to evaluate against the selected policies.
    #[arg(long)]
    pub(crate) action: String,

    /// Resource VDT to evaluate.
    #[arg(long)]
    pub(crate) resource_vrn: String,

    /// Optional caller/principal attributes as JSON.
    #[arg(long)]
    pub(crate) caller_attrs: Option<String>,

    /// Optional resource attributes as JSON.
    #[arg(long)]
    pub(crate) resource_attrs: Option<String>,

    /// Optional request attributes as JSON.
    #[arg(long)]
    pub(crate) request_attrs: Option<String>,

    /// Emit machine-readable JSON to stdout.
    #[arg(long)]
    pub(crate) json: bool,

    #[command(flatten)]
    pub(crate) api: PolicyApiArgs,
}

pub(crate) async fn run_async(args: PolicyEvaluateArgs) -> Result<(), CliError> {
    let has_remote_selectors =
        !args.selectors.policy_ids.is_empty() || !args.selectors.names.is_empty();
    if args.file.is_some() == has_remote_selectors {
        return Err(CliError::user(
            "provide either --file or at least one --policy-id/--name selector",
        ));
    }

    let client = resolve_client(&args.api)?;
    let policies = if let Some(path) = &args.file {
        load_policy_specs_from_path(path)?
    } else {
        let remote = fetch_remote_policies(&client).await?;
        remote_policies_to_specs(&remote, &args.selectors)?
    };
    if policies.is_empty() {
        return Err(CliError::user("no policies selected for evaluation"));
    }

    let statements = flatten_policy_statements(&policies)?;
    let caller_attrs =
        parse_optional_json_arg::<serde_json::Value>("--caller-attrs", args.caller_attrs)?;
    let resource_attrs =
        parse_optional_json_arg::<serde_json::Value>("--resource-attrs", args.resource_attrs)?;
    let request_attrs =
        parse_optional_json_arg::<serde_json::Value>("--request-attrs", args.request_attrs)?;

    let mut payload = serde_json::json!({
        "action": args.action,
        "resource_vrn": args.resource_vrn,
        "statements": statements,
    });
    if let Some(caller_attrs) = caller_attrs {
        payload["caller"] = caller_attrs;
    }
    if let Some(resource_attrs) = resource_attrs {
        payload["resource"] = resource_attrs;
    }
    if let Some(request_attrs) = request_attrs {
        payload["request"] = request_attrs;
    }

    let result = client
        .post_json_value("/v1/policies/simulate", &payload)
        .await?;
    if args.json {
        return print_json(&result);
    }

    let decision = result.get("decision").unwrap_or(&result);
    let allowed = decision
        .get("allowed")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    println!("decision: {}", if allowed { "allow" } else { "deny" });
    println!(
        "type:     {}",
        decision
            .get("decision")
            .and_then(|value| value.as_str())
            .unwrap_or("-")
    );
    if let Some(reason) = decision.get("reason").and_then(|value| value.as_str()) {
        println!("reason:   {reason}");
    }
    if let Some(policy_id) = decision
        .get("matched_policy_id")
        .and_then(|value| value.as_str())
    {
        println!("policy:   {policy_id}");
    }
    if let Some(statement_sid) = decision
        .get("matched_statement_sid")
        .and_then(|value| value.as_str())
    {
        println!("statement:{statement_sid}");
    }
    Ok(())
}

fn parse_optional_json_arg<T: DeserializeOwned>(
    flag: &str,
    raw: Option<String>,
) -> Result<Option<T>, CliError> {
    raw.map(|raw| {
        serde_json::from_str::<T>(&raw)
            .map_err(|error| CliError::user(format!("invalid {flag} JSON: {error}")))
    })
    .transpose()
}
