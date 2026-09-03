// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use clap::Args;

use crate::api::AsyncApiClient;
use crate::config::{Config, ConfigInputs};
use crate::error::CliError;
use crate::managed::control_manifest::{ControlManifest, IamPolicySpec, IamSpec, Resources};
use crate::managed::control_reconcile::{
    ReconcileAction, ReconcileOp, ReconcilePlan, ReconcileResult,
};

#[derive(Debug, Clone, Args)]
pub(crate) struct PolicyApiArgs {
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

#[derive(Debug, Clone, Default, Args)]
pub(crate) struct PolicyRemoteSelectorArgs {
    /// Select one or more remote policies by ID.
    #[arg(long = "policy-id", value_name = "POLICY_ID")]
    pub(crate) policy_ids: Vec<String>,

    /// Select one or more remote policies by name.
    #[arg(long = "name", value_name = "NAME")]
    pub(crate) names: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyFileFormat {
    Json,
    Yaml,
}

impl PolicyFileFormat {
    pub(crate) fn infer_from_path(path: &std::path::Path) -> Option<Self> {
        match path.extension().and_then(|value| value.to_str()) {
            Some("json") => Some(Self::Json),
            Some("yaml") | Some("yml") => Some(Self::Yaml),
            _ => None,
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, CliError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "yaml" | "yml" => Ok(Self::Yaml),
            other => Err(CliError::user(format!(
                "unsupported policy format {other:?}; expected json or yaml"
            ))),
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct RemotePolicyRecord {
    #[serde(default)]
    pub(crate) policy_id: Option<String>,
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default)]
    pub(crate) statements: Option<serde_json::Value>,
}

impl RemotePolicyRecord {
    fn resolved_id(&self) -> Option<&str> {
        self.policy_id.as_deref()
    }
}

pub(crate) fn resolve_client(args: &PolicyApiArgs) -> Result<AsyncApiClient, CliError> {
    let inputs = ConfigInputs {
        api_url_flag: args.api_url.clone(),
        api_token_flag: args.api_token.clone(),
        config_path: args.config.clone(),
        profile_flag: Some(args.profile.clone()),
        region_flag: args.region.clone(),
    };
    let config = Config::resolve(inputs)?;
    let api_token = config.api_token.ok_or_else(|| {
        CliError::auth("missing api token (set VERDICTAN_API_TOKEN or run `verdictan auth login`)")
    })?;
    Ok(AsyncApiClient::new(config.api_url, api_token)?.with_region(config.region.clone()))
}

pub(crate) async fn fetch_remote_policies(
    client: &AsyncApiClient,
) -> Result<Vec<RemotePolicyRecord>, CliError> {
    let value = client.get_json_value("/v1/policies").await?;
    let policies = value
        .get("policies")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    policies
        .into_iter()
        .map(|value| {
            serde_json::from_value::<RemotePolicyRecord>(value).map_err(|error| {
                CliError::internal(format!("invalid /v1/policies response: {error}"))
            })
        })
        .collect()
}

pub(crate) fn remote_policies_to_specs(
    remote: &[RemotePolicyRecord],
    selectors: &PolicyRemoteSelectorArgs,
) -> Result<Vec<IamPolicySpec>, CliError> {
    if selectors.policy_ids.is_empty() && selectors.names.is_empty() {
        return Ok(remote
            .iter()
            .filter_map(remote_policy_to_spec)
            .collect::<Vec<_>>());
    }

    let mut specs = Vec::new();

    for policy_id in &selectors.policy_ids {
        let record = remote
            .iter()
            .find(|record| record.resolved_id() == Some(policy_id.as_str()))
            .ok_or_else(|| CliError::user(format!("remote policy {policy_id:?} not found")))?;
        if let Some(spec) = remote_policy_to_spec(record) {
            specs.push(spec);
        }
    }

    for name in &selectors.names {
        let record = remote
            .iter()
            .find(|record| record.name.as_deref() == Some(name.as_str()))
            .ok_or_else(|| CliError::user(format!("remote policy {name:?} not found")))?;
        if let Some(spec) = remote_policy_to_spec(record) {
            specs.push(spec);
        }
    }

    Ok(specs)
}

fn remote_policy_to_spec(record: &RemotePolicyRecord) -> Option<IamPolicySpec> {
    Some(IamPolicySpec {
        name: record.name.clone()?,
        description: record.description.clone(),
        statements: record.statements.clone(),
    })
}

pub(crate) fn load_policy_specs_from_path(
    path: &std::path::Path,
) -> Result<Vec<IamPolicySpec>, CliError> {
    let content = std::fs::read_to_string(path)
        .map_err(|error| CliError::user(format!("failed to read {}: {error}", path.display())))?;
    let format = PolicyFileFormat::infer_from_path(path).unwrap_or(PolicyFileFormat::Yaml);
    let value = match format {
        PolicyFileFormat::Json => {
            serde_json::from_str::<serde_json::Value>(&content).map_err(|error| {
                CliError::user(format!(
                    "failed to parse {} as JSON: {error}",
                    path.display()
                ))
            })?
        }
        PolicyFileFormat::Yaml => {
            let yaml = serde_yaml::from_str::<serde_yaml::Value>(&content).map_err(|error| {
                CliError::user(format!(
                    "failed to parse {} as YAML: {error}",
                    path.display()
                ))
            })?;
            serde_json::to_value(yaml)
                .map_err(|error| CliError::internal(format!("failed to normalize YAML: {error}")))?
        }
    };
    parse_policy_specs_value(&value)
}

pub(crate) fn parse_policy_specs_value(
    value: &serde_json::Value,
) -> Result<Vec<IamPolicySpec>, CliError> {
    if let Some(array) = value.as_array() {
        return array
            .iter()
            .map(parse_single_policy_spec)
            .collect::<Result<Vec<_>, _>>();
    }

    let Some(object) = value.as_object() else {
        return Err(CliError::user(
            "expected a policy object, a policies array, or an iam bundle",
        ));
    };

    if object.contains_key("policies") {
        let spec: IamSpec = serde_json::from_value(value.clone())
            .map_err(|error| CliError::user(format!("failed to parse policy bundle: {error}")))?;
        return Ok(spec.policies);
    }

    Ok(vec![parse_single_policy_spec(value)?])
}

fn parse_single_policy_spec(value: &serde_json::Value) -> Result<IamPolicySpec, CliError> {
    let object = value.as_object().ok_or_else(|| {
        CliError::user("expected a policy object with name and statements fields")
    })?;
    let name = object
        .get("name")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::user("policy document is missing a non-empty name"))?
        .to_string();
    let description = object
        .get("description")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let statements = if let Some(value) = object.get("statements") {
        Some(value.clone())
    } else if object.contains_key("Statement") || object.contains_key("Version") {
        let mut document = serde_json::Map::new();
        if let Some(version) = object.get("Version") {
            document.insert("Version".to_string(), version.clone());
        }
        if let Some(statement) = object.get("Statement") {
            document.insert("Statement".to_string(), statement.clone());
        }
        Some(serde_json::Value::Object(document))
    } else {
        None
    };

    Ok(IamPolicySpec {
        name,
        description,
        statements,
    })
}

pub(crate) fn write_policy_specs_to_path(
    path: &std::path::Path,
    policies: &[IamPolicySpec],
    format: Option<PolicyFileFormat>,
) -> Result<(), CliError> {
    let format = format
        .or_else(|| PolicyFileFormat::infer_from_path(path))
        .unwrap_or(PolicyFileFormat::Yaml);
    let payload = if policies.len() == 1 {
        serde_json::to_value(&policies[0])
            .map_err(|error| CliError::internal(format!("failed to serialize policy: {error}")))?
    } else {
        serde_json::to_value(IamSpec {
            policies: policies.to_vec(),
            roles: vec![],
        })
        .map_err(|error| CliError::internal(format!("failed to serialize policies: {error}")))?
    };
    let rendered = match format {
        PolicyFileFormat::Json => serde_json::to_string_pretty(&payload)
            .map_err(|error| CliError::internal(format!("failed to encode JSON: {error}")))?,
        PolicyFileFormat::Yaml => serde_yaml::to_string(&payload)
            .map_err(|error| CliError::internal(format!("failed to encode YAML: {error}")))?,
    };
    std::fs::write(path, rendered)
        .map_err(|error| CliError::user(format!("failed to write {}: {error}", path.display())))
}

pub(crate) fn build_policy_manifest(policies: &[IamPolicySpec]) -> ControlManifest {
    ControlManifest {
        version: "1".to_string(),
        resources: Resources {
            iam: Some(IamSpec {
                policies: policies.to_vec(),
                roles: vec![],
            }),
            ..Resources::default()
        },
    }
}

pub(crate) fn filter_policy_plan(plan: &ReconcilePlan) -> ReconcilePlan {
    ReconcilePlan {
        ops: plan
            .ops
            .iter()
            .filter(|op| op.resource_type == "iam.policy")
            .cloned()
            .collect(),
    }
}

pub(crate) fn build_plan_json(plan: &ReconcilePlan, prune: bool) -> serde_json::Value {
    serde_json::json!({
        "dry_run": true,
        "prune": prune,
        "summary": {
            "creates": plan.creates(),
            "updates": plan.updates(),
            "deletes": plan.deletions(),
            "no_ops": plan.no_ops(),
        },
        "ops": &plan.ops,
    })
}

pub(crate) fn render_plan_text(plan: &ReconcilePlan, apply_hint: &str) -> String {
    if !plan.has_changes() {
        return "no changes — policies are up to date\n".to_string();
    }

    let mut rendered = format!(
        "plan: {} create(s)  {} update(s)  {} delete(s)  {} no-op(s)\n\n",
        plan.creates(),
        plan.updates(),
        plan.deletions(),
        plan.no_ops(),
    );
    for line in plan.ops.iter().filter_map(format_plan_op_line) {
        rendered.push_str(&line);
        rendered.push('\n');
    }
    rendered.push('\n');
    rendered.push_str(apply_hint);
    rendered.push('\n');
    rendered
}

pub(crate) fn build_apply_json_summary(
    plan: &ReconcilePlan,
    result: &ReconcileResult,
    prune: bool,
) -> serde_json::Value {
    serde_json::json!({
        "applied": !result.has_failures(),
        "prune": prune,
        "summary": {
            "creates": plan.creates(),
            "updates": plan.updates(),
            "deletes": plan.deletions(),
            "no_ops": plan.no_ops(),
        },
        "successful": &result.successful,
        "failed": &result.failed,
    })
}

pub(crate) fn render_apply_preview(plan: &ReconcilePlan) -> String {
    let mut rendered = format!(
        "plan: {} create(s)  {} update(s)  {} delete(s)  {} no-op(s)\n\n",
        plan.creates(),
        plan.updates(),
        plan.deletions(),
        plan.no_ops(),
    );
    for line in plan.ops.iter().filter_map(format_plan_op_line) {
        rendered.push_str(&line);
        rendered.push('\n');
    }
    rendered.push('\n');
    rendered
}

pub(crate) fn count_applied_ops(result: &ReconcileResult) -> usize {
    result
        .successful
        .iter()
        .filter(|op| op.action != ReconcileAction::NoOp)
        .count()
}

pub(crate) fn confirm_apply(prune: bool) -> Result<bool, CliError> {
    let stdout = std::io::stdout();
    let stdin = std::io::stdin();
    let mut stdout = stdout.lock();
    let mut stdin = stdin.lock();
    confirm_apply_with_io(prune, &mut stdin, &mut stdout)
}

pub(crate) fn flatten_policy_statements(
    policies: &[IamPolicySpec],
) -> Result<serde_json::Value, CliError> {
    let mut statements = Vec::new();
    for policy in policies {
        let value = policy.statements.as_ref().ok_or_else(|| {
            CliError::user(format!(
                "policy {:?} is missing statements; run `verdictan policy lint` first",
                policy.name
            ))
        })?;
        statements.extend(extract_statement_values(value)?);
    }
    Ok(serde_json::Value::Array(statements))
}

pub(crate) fn lint_policy_specs(policies: &[IamPolicySpec]) -> Vec<String> {
    let mut errors = Vec::new();

    if policies.is_empty() {
        errors.push("no policies found".to_string());
        return errors;
    }

    for policy in policies {
        if policy.name.trim().is_empty() {
            errors.push("policy name must not be empty".to_string());
        }
        match policy.statements.as_ref() {
            Some(value) => {
                let validation_errors =
                    crate::policy::iam_validation::validate_statement_document(value);
                errors.extend(
                    validation_errors
                        .into_iter()
                        .map(|error| format!("policy {:?}: {error}", policy.name)),
                );
            }
            None => errors.push(format!("policy {:?} is missing statements", policy.name)),
        }
    }

    errors
}

fn extract_statement_values(value: &serde_json::Value) -> Result<Vec<serde_json::Value>, CliError> {
    if let Some(array) = value.as_array() {
        return Ok(array.clone());
    }
    if let Some(object) = value.as_object() {
        if let Some(statements) = object.get("Statement").or_else(|| object.get("statements")) {
            return statements
                .as_array()
                .cloned()
                .ok_or_else(|| CliError::user("policy document Statement field must be an array"));
        }
        if object.contains_key("effect") || object.contains_key("Effect") {
            return Ok(vec![value.clone()]);
        }
    }
    Err(CliError::user(
        "policy statements must be an array or a document with Statement/statements",
    ))
}

fn format_plan_op_line(op: &ReconcileOp) -> Option<String> {
    if op.action == ReconcileAction::NoOp {
        return None;
    }

    let marker = match op.action {
        ReconcileAction::Create => "+",
        ReconcileAction::Update => "~",
        ReconcileAction::Delete => "-",
        ReconcileAction::NoOp => " ",
    };
    let mut rendered = format!("{marker} {}  {}", op.resource_type, op.name);
    if let Some(detail) = op.detail.as_deref() {
        if is_structured_diff_detail(detail) {
            for line in detail.lines().filter(|line| !line.trim().is_empty()) {
                rendered.push('\n');
                rendered.push_str("    ");
                rendered.push_str(line);
            }
        } else {
            rendered.push_str(&format!("  ({detail})"));
        }
    }
    Some(rendered)
}

fn is_structured_diff_detail(detail: &str) -> bool {
    !detail.is_empty() && detail.lines().all(is_structured_diff_detail_line)
}

fn is_structured_diff_detail_line(line: &str) -> bool {
    line.strip_prefix("+ ")
        .or_else(|| line.strip_prefix("- "))
        .or_else(|| line.strip_prefix("~ "))
        .is_some()
}

fn confirm_apply_with_io<R, W>(prune: bool, input: &mut R, output: &mut W) -> Result<bool, CliError>
where
    R: std::io::BufRead,
    W: std::io::Write,
{
    let prompt = if prune {
        "This will create, update, AND DELETE policies listed above.\nType 'yes' to continue: "
    } else {
        "This will create and update policies listed above.\nType 'yes' to continue: "
    };

    output
        .write_all(prompt.as_bytes())
        .map_err(|error| CliError::internal(format!("write failed: {error}")))?;
    output
        .flush()
        .map_err(|error| CliError::internal(format!("flush failed: {error}")))?;

    let mut line = String::new();
    input
        .read_line(&mut line)
        .map_err(|error| CliError::internal(format!("read failed: {error}")))?;
    Ok(line.trim().eq_ignore_ascii_case("yes"))
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

    #[test]
    fn parse_policy_specs_value_accepts_bundle() {
        let value = serde_json::json!({
            "policies": [
                {
                    "name": "Gateway Reader",
                    "description": "Read gateway events",
                    "statements": [{
                        "effect": "allow",
                        "actions": ["events:read"],
                        "resources": ["*"],
                        "conditions": {}
                    }]
                }
            ],
            "roles": []
        });

        let specs = parse_policy_specs_value(&value).unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "Gateway Reader");
    }

    #[test]
    fn flatten_policy_statements_extracts_statement_documents() {
        let policies = vec![IamPolicySpec {
            name: "Gateway Reader".into(),
            description: None,
            statements: Some(serde_json::json!({
                "Version": "2026-05-11",
                "Statement": [{
                    "effect": "allow",
                    "actions": ["events:read"],
                    "resources": ["*"],
                    "conditions": {}
                }]
            })),
        }];

        let flattened = flatten_policy_statements(&policies).unwrap();
        assert_eq!(flattened.as_array().unwrap().len(), 1);
    }

    #[test]
    fn lint_policy_specs_reports_missing_statements() {
        let policies = vec![IamPolicySpec {
            name: "Broken".into(),
            description: None,
            statements: None,
        }];

        let errors = lint_policy_specs(&policies);
        assert!(errors
            .iter()
            .any(|error| error.contains("missing statements")));
    }
}
