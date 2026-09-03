// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! `verdictan gateway check` — dry-run gateway validation without starting.
//!
//! Parses the policy config, resolves credentials, and reports readiness
//! without actually starting the gateway server.

use clap::Args;

use crate::error::CliError;
use crate::gateway::declarative_config::LoadedDeclarativeConfig;
use crate::gateway::providers::{ProviderRegistry, ProviderTarget};

#[derive(Debug, Args)]
pub(crate) struct GatewayCheckArgs {
    /// Path to the policy config file.
    #[arg(long, default_value = "policy-config.yaml")]
    pub config: String,

    /// Show verbose output that includes all provider details.
    #[arg(long)]
    pub verbose: bool,
}

pub(crate) fn run(args: GatewayCheckArgs) -> Result<(), CliError> {
    let config_path = std::path::Path::new(&args.config);
    if !config_path.exists() {
        return Err(CliError::user(format!(
            "config file not found: {}",
            args.config
        )));
    }

    let loaded = LoadedDeclarativeConfig::from_path(config_path)?;
    let ready = is_gateway_ready(&loaded);
    for line in build_report_lines(&args.config, &loaded, args.verbose) {
        println!("{line}");
    }

    if !ready {
        return Err(CliError::user("gateway is not ready"));
    }
    Ok(())
}

fn is_gateway_ready(loaded: &LoadedDeclarativeConfig) -> bool {
    match &loaded.provider_registry {
        None => false,
        Some(registry) => {
            let summary = summarize_provider_registry(registry);
            summary.required_missing.is_empty() && !summary.active.is_empty()
        }
    }
}

fn build_report_lines(
    config_name: &str,
    loaded: &LoadedDeclarativeConfig,
    verbose: bool,
) -> Vec<String> {
    let mut lines = vec![
        format!("Config file: {} (valid)", config_name),
        format!("  Version: {}", loaded.config_version),
        format!("  SHA256:  {}", loaded.config_sha256),
        String::new(),
    ];

    match loaded.provider_registry.as_ref() {
        Some(registry) => push_registry_report(&mut lines, loaded, registry, verbose),
        None => push_missing_provider_report(&mut lines),
    }

    lines
}

fn push_registry_report(
    lines: &mut Vec<String>,
    loaded: &LoadedDeclarativeConfig,
    registry: &ProviderRegistry,
    verbose: bool,
) {
    let summary = summarize_provider_registry(registry);
    push_active_provider_lines(lines, &summary, verbose);
    push_inactive_provider_lines(lines, &summary);
    push_routing_lines(lines, registry);
    push_policy_chain_lines(lines, loaded, verbose);
    push_status_lines(lines, &summary);
}

fn push_missing_provider_report(lines: &mut Vec<String>) {
    lines.push("No providers section found.".to_string());
    lines.push(String::new());
    lines.push("\u{2717} Status: Not Ready".to_string());
    lines.push("  - No providers configured".to_string());
}

fn push_active_provider_lines(
    lines: &mut Vec<String>,
    summary: &ProviderRegistrySummary<'_>,
    verbose: bool,
) {
    lines.push(format!("Active providers ({}):", summary.active.len()));
    for target in &summary.active {
        lines.push(format!("  \u{2713} {}", target.id));
        if verbose {
            lines.push(format!(
                "      provider: {}, model: {}",
                target.provider, target.model
            ));
            lines.push(format!("      base_url: {}", target.base_url));
            lines.push(format!("      timeout:  {:?}", target.timeout));
        }
    }
    lines.push(String::new());
}

fn push_inactive_provider_lines(lines: &mut Vec<String>, summary: &ProviderRegistrySummary<'_>) {
    if summary.inactive.is_empty() {
        return;
    }

    lines.push(format!("Inactive providers ({}):", summary.inactive.len()));
    for provider in &summary.inactive {
        lines.push(format!("  \u{2717} {} — {}", provider.id, provider.reason));
    }
    lines.push(String::new());
}

fn push_routing_lines(lines: &mut Vec<String>, registry: &ProviderRegistry) {
    lines.push(format!("Routing strategy: {:?}", registry.routing.strategy));
    lines.push(String::new());
}

fn push_policy_chain_lines(
    lines: &mut Vec<String>,
    loaded: &LoadedDeclarativeConfig,
    verbose: bool,
) {
    lines.push(format!(
        "Policy chain: {} rule(s)",
        loaded.chain_entries.len()
    ));
    if verbose {
        for (index, entry) in loaded.chain_entries.iter().enumerate() {
            lines.push(format!("  [{}] {}", index + 1, entry.kind()));
        }
    }
    lines.push(String::new());
}

fn push_status_lines(lines: &mut Vec<String>, summary: &ProviderRegistrySummary<'_>) {
    if summary.required_missing.is_empty() && !summary.active.is_empty() {
        lines.push("\u{2713} Status: Ready".to_string());
        return;
    }

    lines.push("\u{2717} Status: Not Ready".to_string());
    if summary.active.is_empty() {
        lines.push("  - No active providers with resolved credentials".to_string());
    }
    for id in &summary.required_missing {
        lines.push(format!(
            "  - Required provider '{}' has unresolved credentials",
            id
        ));
    }
}

fn summarize_provider_registry(registry: &ProviderRegistry) -> ProviderRegistrySummary<'_> {
    let mut active = Vec::new();
    let mut inactive = Vec::new();
    let mut required_missing = Vec::new();

    for target in &registry.targets {
        match classify_provider(target) {
            ProviderClassification::Active => active.push(target),
            ProviderClassification::Inactive(reason) => {
                inactive.push(InactiveProvider {
                    id: target.id.as_str(),
                    reason,
                });
                if target.required {
                    required_missing.push(target.id.as_str());
                }
            }
        }
    }

    ProviderRegistrySummary {
        active,
        inactive,
        required_missing,
    }
}

fn classify_provider(target: &ProviderTarget) -> ProviderClassification {
    if !target.api_key.is_empty() || !target.requires_resolved_api_key() {
        ProviderClassification::Active
    } else if target.secret_key_ref.is_some() {
        ProviderClassification::Inactive("credential unresolved")
    } else {
        ProviderClassification::Inactive("no api_key or secret_key_ref")
    }
}

struct ProviderRegistrySummary<'a> {
    active: Vec<&'a ProviderTarget>,
    inactive: Vec<InactiveProvider<'a>>,
    required_missing: Vec<&'a str>,
}

struct InactiveProvider<'a> {
    id: &'a str,
    reason: &'static str,
}

enum ProviderClassification {
    Active,
    Inactive(&'static str),
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
    use super::build_report_lines;
    use super::GatewayCheckArgs;
    use crate::gateway::declarative_config::LoadedDeclarativeConfig;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn report_marks_missing_providers_not_ready() {
        let loaded = load_config(
            r#"
pack:
  name: gateway-check
  version: "1.0.0"
"#,
        );

        let lines = build_report_lines("policy-config.yaml", &loaded, false);

        assert!(lines.contains(&"No providers section found.".to_string()));
        assert!(lines.contains(&"\u{2717} Status: Not Ready".to_string()));
        assert!(lines.contains(&"  - No providers configured".to_string()));
    }

    #[test]
    fn report_renders_verbose_provider_readiness() {
        let loaded = load_config(
            r#"
pack:
  name: gateway-check
  version: "1.0.0"
providers:
  targets:
    - id: optional-openai
      provider: openai
      model: gpt-5.4-mini
      base_url: https://api.openai.com/v1
    - id: required-anthropic
      provider: anthropic
      model: claude-3-7-sonnet-latest
      base_url: https://api.anthropic.com
      required: true
      secret_key_ref:
        store: ANTHROPIC_API_KEY
"#,
        );

        let lines = build_report_lines("policy-config.yaml", &loaded, true);

        assert!(lines.contains(&"Active providers (1):".to_string()));
        assert!(lines.contains(&"  \u{2713} optional-openai".to_string()));
        assert!(lines.contains(&"      provider: openai, model: gpt-5.4-mini".to_string()));
        assert!(lines.contains(&"Inactive providers (1):".to_string()));
        assert!(
            lines.contains(&"  \u{2717} required-anthropic — credential unresolved".to_string())
        );
        assert!(lines.contains(&"\u{2717} Status: Not Ready".to_string()));
        assert!(lines.contains(
            &"  - Required provider 'required-anthropic' has unresolved credentials".to_string()
        ));
    }

    fn load_config(yaml: &str) -> LoadedDeclarativeConfig {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("policy-config.yaml");
        fs::write(&path, yaml.trim_start()).expect("write config");
        LoadedDeclarativeConfig::from_path(&path).expect("load config")
    }

    #[test]
    fn run_reports_missing_config_file() {
        let err = super::run(GatewayCheckArgs {
            config: "missing-policy-config.yaml".to_string(),
            verbose: false,
        })
        .expect_err("missing config should fail");
        assert!(err.to_string().contains("config file not found"));
    }

    #[test]
    fn run_succeeds_for_valid_on_disk_config() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("policy-config.yaml");
        fs::write(
            &path,
            r#"
pack:
  name: gateway-check
  version: "1.0.0"
providers:
  targets:
    - id: optional-openai
      provider: openai
      model: gpt-5.4-mini
      base_url: https://api.openai.com/v1
"#,
        )
        .expect("write config");

        super::run(GatewayCheckArgs {
            config: path.display().to_string(),
            verbose: false,
        })
        .expect("gateway check succeeds");
    }

    #[test]
    fn report_verbose_includes_routing_and_policy_chain_details() {
        let loaded = load_config(
            r#"
pack:
  name: gateway-check
  version: "1.0.0"
policies:
  chain:
    - prompt-injection
    - pii-detector
providers:
  routing:
    strategy: round_robin
  targets:
    - id: optional-openai
      provider: openai
      model: gpt-5.4-mini
      base_url: https://api.openai.com/v1
      api_key: inline-key
      timeout: 30s
"#,
        );

        let lines = build_report_lines("policy-config.yaml", &loaded, true);

        assert!(lines.iter().any(|line| line.contains("Routing strategy:")));
        assert!(lines
            .iter()
            .any(|line| line.contains("Policy chain: 2 rule(s)")));
        assert!(lines
            .iter()
            .any(|line| line.contains("[1] prompt-injection")));
        assert!(lines.iter().any(|line| line.contains("timeout:")));
    }

    #[test]
    fn report_marks_not_ready_when_required_credentials_missing() {
        let loaded = load_config(
            r#"
pack:
  name: gateway-check
  version: "1.0.0"
providers:
  targets:
    - id: required-anthropic
      provider: anthropic
      model: claude-3-7-sonnet-latest
      base_url: https://api.anthropic.com
      required: true
      secret_key_ref:
        store: ANTHROPIC_API_KEY
"#,
        );

        let lines = build_report_lines("policy-config.yaml", &loaded, false);

        assert!(lines.contains(&"\u{2717} Status: Not Ready".to_string()));
        assert!(lines.contains(
            &"  - Required provider 'required-anthropic' has unresolved credentials".to_string()
        ));
    }

    #[test]
    fn report_marks_ready_when_active_providers_present() {
        let loaded = load_config(
            r#"
pack:
  name: gateway-check
  version: "1.0.0"
providers:
  targets:
    - id: optional-openai
      provider: openai
      model: gpt-5.4-mini
      base_url: https://api.openai.com/v1
      api_key: inline-key
"#,
        );

        let lines = build_report_lines("policy-config.yaml", &loaded, false);

        assert!(lines.contains(&"\u{2713} Status: Ready".to_string()));
        assert!(lines.contains(&"Active providers (1):".to_string()));
        assert!(!lines.iter().any(|line| line.contains("Inactive providers")));
    }

    #[test]
    fn build_report_lines_includes_config_name_and_version() {
        let loaded = load_config(
            r#"
pack:
  name: gateway-check
  version: "2.5.0"
providers:
  targets:
    - id: test-provider
      provider: openai
      model: gpt-5.4
      base_url: https://api.openai.com/v1
      api_key: key
"#,
        );
        let lines = build_report_lines("custom-config.yaml", &loaded, false);
        assert!(lines.iter().any(|line| line.contains("custom-config.yaml")));
        assert!(lines.iter().any(|line| line.contains("Version:")));
        assert!(lines.iter().any(|line| line.contains("SHA256:")));
    }

    #[test]
    fn run_with_invalid_yaml_reports_parse_error() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("bad.yaml");
        fs::write(&path, "not: valid: yaml: [[[[").expect("write");

        let err = super::run(GatewayCheckArgs {
            config: path.display().to_string(),
            verbose: false,
        })
        .expect_err("bad yaml should fail");
        let msg = err.to_string();
        assert!(!msg.is_empty());
    }

    #[test]
    fn report_non_verbose_excludes_timeout_detail() {
        let loaded = load_config(
            r#"
pack:
  name: gateway-check
  version: "1.0.0"
providers:
  targets:
    - id: optional-openai
      provider: openai
      model: gpt-5.4-mini
      base_url: https://api.openai.com/v1
      api_key: key
      timeout: 30s
"#,
        );
        let lines = build_report_lines("policy-config.yaml", &loaded, false);
        assert!(!lines.iter().any(|line| line.contains("timeout:")));
    }

    #[test]
    fn args_debug_impl() {
        let args = GatewayCheckArgs {
            config: "policy.yaml".to_string(),
            verbose: true,
        };
        let debug = format!("{:?}", args);
        assert!(debug.contains("policy.yaml"));
        assert!(debug.contains("true"));
    }
}
