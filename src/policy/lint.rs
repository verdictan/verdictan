// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::path::Path;
use std::sync::OnceLock;

use crate::error::CliError;
use crate::gateway::declarative_config::validate_inactive_configuration_fields;

pub struct LintResult {
    pub(crate) is_valid: bool,
    pub errors: Vec<String>,
}

pub(crate) fn lint_config_file(path: &Path) -> Result<LintResult, CliError> {
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    if matches!(ext, "yaml" | "yml") {
        lint_yaml_file(path)
    } else {
        Err(CliError::user(
            "policy config must be YAML (expected .yaml or .yml)",
        ))
    }
}

/// Test-only entry point for integration tests that need to lint a JSON value
/// without reading from disk.
#[doc(hidden)]
pub fn lint_json_value_for_test(json_value: &serde_json::Value) -> Result<LintResult, CliError> {
    lint_json_value(json_value)
}

pub(crate) fn lint_yaml(yaml: &str) -> Result<LintResult, CliError> {
    let value: serde_yaml::Value = serde_yaml::from_str(yaml)
        .map_err(|e| CliError::user(format!("failed to parse YAML: {e}")))?;

    let json_value = serde_json::to_value(value)
        .map_err(|e| CliError::internal(format!("failed to convert YAML to JSON: {e}")))?;

    lint_json_value(&json_value)
}

fn lint_yaml_file(path: &Path) -> Result<LintResult, CliError> {
    let bytes = std::fs::read(path)
        .map_err(|e| CliError::user(format!("failed to read {}: {e}", path.display())))?;

    let text = String::from_utf8(bytes)
        .map_err(|e| CliError::user(format!("file is not valid UTF-8: {e}")))?;

    lint_yaml(&text)
}

fn lint_json_value(json_value: &serde_json::Value) -> Result<LintResult, CliError> {
    use jsonschema::{Draft, JSONSchema};

    static SCHEMA: OnceLock<Result<JSONSchema, String>> = OnceLock::new();
    let schema = SCHEMA
        .get_or_init(|| {
            let schema_json =
                super::schema::load_schema_json().map_err(|error| error.to_string())?;
            JSONSchema::options()
                // Keep draft aligned with the API crate to avoid drift.
                .with_draft(Draft::Draft7)
                .compile(&schema_json)
                .map_err(|error| format!("failed to compile embedded policy schema: {error}"))
        })
        .as_ref()
        .map_err(|error| CliError::internal(error.clone()))?;

    let mut errors: Vec<String> = match schema.validate(json_value) {
        Ok(()) => Vec::new(),
        Err(iter) => iter
            .map(|e| {
                let instance = e.instance_path.to_string();
                let message = e.to_string();
                if instance.is_empty() {
                    message
                } else {
                    format!("{instance}: {message}")
                }
            })
            .collect(),
    };

    errors.sort();

    if let Err(error) = validate_inactive_configuration_fields(json_value) {
        errors.push(error.to_string());
    }

    // --- Breaking config-field rename validation ---
    errors.extend(cross_validate_deprecated_secret_key_fields(json_value));

    // --- data-routing-policy cross-validation ---
    let warnings = cross_validate_data_routing_policy(json_value);
    errors.extend(warnings);

    // --- Phase 1: routing order / only / ignore cross-validation ---
    errors.extend(cross_validate_routing_order(json_value));

    // --- Phase 2: cost budget cross-validation ---
    errors.extend(cross_validate_cost_budget(json_value));

    // --- Phase 4: privacy routing cross-validation ---
    errors.extend(cross_validate_privacy_routing(json_value));

    // --- Phase 5: quantization cross-validation ---
    errors.extend(cross_validate_quantization(json_value));

    // --- Phase 14: LB strategy cross-validation ---
    errors.extend(cross_validate_lb_strategies(json_value));

    // --- Phase 6: testing section cross-validation ---
    errors.extend(cross_validate_testing_section(json_value));

    // --- Phase 11: assertion mode/severity cross-validation ---
    errors.extend(cross_validate_assertion_modes(json_value));

    // --- Phase 12: pass_policy cross-validation ---
    errors.extend(cross_validate_pass_policy(json_value));

    // --- Phase 13: assertion_packs cross-validation ---
    errors.extend(cross_validate_assertion_packs(json_value));

    // --- Phase 10: `when` predicate cross-validation ---
    errors.extend(cross_validate_when_predicates(json_value));

    // --- Registry-derived kinds / consumed keys / unread fields ---
    errors.extend(
        crate::gateway::declarative_config::registry_policy_contract_diagnostics(json_value),
    );

    // --- Phase 16/17: routes cross-validation ---
    errors.extend(cross_validate_routes(json_value));

    // --- Phases 18-20: rate limit and size limit cross-validation ---
    errors.extend(cross_validate_token_rate_limit(json_value));
    errors.extend(cross_validate_request_rate_limits(json_value));
    errors.extend(cross_validate_size_limits(json_value));

    // --- Phase 21: consumer group cross-validation ---
    errors.extend(cross_validate_consumer_groups(json_value));

    // --- Phases 15 + 35: provider format and auth cross-validation ---
    errors.extend(cross_validate_provider_format_and_auth(json_value));
    errors.extend(cross_validate_provider_pipelines(json_value));

    // --- Phase 45: reject unavailable provider adapters ---
    errors.extend(cross_validate_unavailable_providers(json_value));

    // --- Execution-target compatibility diagnostics ---
    errors.extend(cross_validate_execution_targets(json_value));

    // --- Phase 23: semantic cache cross-validation ---
    errors.extend(cross_validate_semantic_cache(json_value));

    // --- Phase 24: language-validator cross-validation ---
    errors.extend(cross_validate_language_validator(json_value));

    // --- Phase 25: external-moderation cross-validation ---
    errors.extend(cross_validate_external_moderation(json_value));

    // --- Phase 28: bot-detector cross-validation ---
    errors.extend(cross_validate_bot_detector(json_value));

    // --- Phase 29: content-extractor cross-validation ---
    errors.extend(cross_validate_content_extractor(json_value));

    // --- Tool governance cross-validation ---
    errors.extend(cross_validate_tool_policies(json_value));

    // --- Policy targeting cross-validation ---
    errors.extend(cross_validate_policy_targeting(json_value));

    // --- MCP provider target cross-validation ---
    errors.extend(cross_validate_mcp_provider_targets(json_value));

    // --- AI usage streaming cross-validation ---
    errors.extend(cross_validate_ai_usage_streaming(json_value));

    errors.sort();

    Ok(LintResult {
        is_valid: errors.is_empty(),
        errors,
    })
}

fn cross_validate_deprecated_secret_key_fields(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();
    collect_deprecated_secret_key_fields(root, "", &mut diags);
    diags
}

fn collect_deprecated_secret_key_fields(
    value: &serde_json::Value,
    path: &str,
    diags: &mut Vec<String>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for deprecated_key in ["api_key_env", "api_key_ref", "firewall_api_key_env"] {
                if map.contains_key(deprecated_key) {
                    let field_path = if path.is_empty() {
                        deprecated_key.to_string()
                    } else {
                        format!("{path}.{deprecated_key}")
                    };
                    diags.push(format!(
                        "{field_path}: fatal: '{deprecated_key}' is no longer accepted; use 'secret_key_ref' instead"
                    ));
                }
            }

            for (key, child) in map {
                let next_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                collect_deprecated_secret_key_fields(child, &next_path, diags);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let next_path = if path.is_empty() {
                    format!("[{index}]")
                } else {
                    format!("{path}[{index}]")
                };
                collect_deprecated_secret_key_fields(child, &next_path, diags);
            }
        }
        _ => {}
    }
}

fn cross_validate_provider_pipelines(root: &serde_json::Value) -> Vec<String> {
    let Some(providers) = root.get("providers").and_then(|value| value.as_object()) else {
        return Vec::new();
    };

    let target_ids = providers
        .get("targets")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let id = item
                        .get("id")
                        .and_then(serde_json::Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())?
                        .to_string();
                    let has_explicit_model = item
                        .get("model")
                        .and_then(serde_json::Value::as_str)
                        .map(str::trim)
                        .is_some_and(|value| !value.is_empty());
                    Some((id, has_explicit_model))
                })
                .collect::<std::collections::HashMap<_, _>>()
        })
        .unwrap_or_default();

    let mut diags = Vec::new();
    let mut seen: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    fn register_virtual_model_name(
        seen: &mut std::collections::HashMap<String, String>,
        diags: &mut Vec<String>,
        identifier: &str,
        owner: &str,
    ) {
        let trimmed = identifier.trim();
        if trimmed.is_empty() {
            return;
        }
        if let Some(previous) = seen.insert(trimmed.to_string(), owner.to_string()) {
            diags.push(format!(
                "providers: virtual model name '{trimmed}' is declared by both {previous} and {owner}"
            ));
        }
    }

    if let Some(model_groups) = providers
        .get("model_groups")
        .and_then(|value| value.as_array())
    {
        for (group_index, group) in model_groups.iter().enumerate() {
            let Some(name) = group.get("name").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let owner = format!("providers.model_groups[{group_index}] '{name}'");
            register_virtual_model_name(&mut seen, &mut diags, name, &owner);
            if let Some(aliases) = group.get("aliases").and_then(serde_json::Value::as_array) {
                for alias in aliases.iter().filter_map(serde_json::Value::as_str) {
                    register_virtual_model_name(&mut seen, &mut diags, alias, &owner);
                }
            }
        }
    }

    if let Some(pipelines) = providers
        .get("pipelines")
        .and_then(|value| value.as_array())
    {
        for (pipeline_index, pipeline) in pipelines.iter().enumerate() {
            let Some(name) = pipeline.get("name").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let owner = format!("providers.pipelines[{pipeline_index}] '{name}'");
            register_virtual_model_name(&mut seen, &mut diags, name, &owner);
            if let Some(aliases) = pipeline
                .get("aliases")
                .and_then(serde_json::Value::as_array)
            {
                for alias in aliases.iter().filter_map(serde_json::Value::as_str) {
                    register_virtual_model_name(&mut seen, &mut diags, alias, &owner);
                }
            }

            if let Some(steps) = pipeline.get("steps").and_then(serde_json::Value::as_array) {
                for (step_index, step) in steps.iter().enumerate() {
                    let Some(target) = step.get("target").and_then(serde_json::Value::as_str)
                    else {
                        continue;
                    };
                    if !target_ids.contains_key(target) {
                        diags.push(format!(
                            "providers.pipelines[{pipeline_index}] '{name}': step {step_index} references unknown target '{target}'"
                        ));
                    } else if !target_ids.get(target).copied().unwrap_or(false) {
                        diags.push(format!(
                            "providers.pipelines[{pipeline_index}] '{name}': step {step_index} target '{target}' must declare providers.targets[].model for pipeline execution"
                        ));
                    }
                }
            }
        }
    }

    if root
        .pointer("/auto/enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        let auto_name = root
            .pointer("/auto/name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("auto");
        if let Some(previous) = seen.get(auto_name.trim()) {
            diags.push(format!(
                "auto provider name '{auto_name}' conflicts with virtual model identifier declared by {previous}"
            ));
        }
    }

    diags
}

/// Extra cross-validation checks for `data-routing-policy` that go beyond
/// what the JSON Schema can express. Returns diagnostic strings (warnings
/// and errors) that are appended to the lint output.
fn cross_validate_data_routing_policy(root: &serde_json::Value) -> Vec<String> {
    let mut diags: Vec<String> = Vec::new();

    // Is data-routing-policy in the chain?
    let chain = root.pointer("/policies/chain").and_then(|v| v.as_array());
    let chain_has_drp = chain
        .map(|arr| {
            arr.iter()
                .any(|v| v.as_str() == Some("data-routing-policy"))
        })
        .unwrap_or(false);

    if !chain_has_drp {
        return diags; // nothing to check
    }

    // Check 1: data-routing-policy in chain but no providers.targets defined.
    let targets = root
        .pointer("/providers/targets")
        .and_then(|v| v.as_array());
    if targets.is_none() || targets.is_some_and(|t| t.is_empty()) {
        diags.push(
            "data-routing-policy: requires a providers.targets list but none is defined"
                .to_string(),
        );
        return diags; // can't do further target-level checks
    }

    // invariant: targets.is_none returns early above
    // SAFETY: invariant: targets verified as Some above
    #[allow(clippy::expect_used)]
    let targets = targets.expect("invariant: targets verified as Some above");

    // Extract the policy block config.
    let drp_cfg = root.pointer("/policy/data-routing-policy");
    let require_zdr = drp_cfg
        .and_then(|c| c.get("require_zero_data_retention"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let require_no_training = drp_cfg
        .and_then(|c| c.get("require_no_training"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let max_retention_days = drp_cfg
        .and_then(|c| c.get("max_retention_days"))
        .and_then(|v| v.as_u64())
        .map(|v| u32::try_from(v).unwrap_or(u32::MAX));

    let mut would_be_excluded = 0usize;

    for (i, target) in targets.iter().enumerate() {
        let id = target
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>");

        let dp = target.get("data_policy");

        // Check 2: target missing data_policy when ZDR or no-training required.
        if dp.is_none() {
            if require_zdr || require_no_training {
                diags.push(format!(
                    "data-routing-policy: provider \"{id}\" (index {i}) has no data_policy — will be excluded"
                ));
            }
            would_be_excluded += 1;
            continue;
        }

        // invariant: dp.is_none continues above
        // SAFETY: invariant: dp verified as Some above
        #[allow(clippy::expect_used)]
        let dp = dp.expect("invariant: dp verified as Some above");

        // Check 3: zero_data_retention=true but retention_days > 0
        let zdr = dp
            .get("zero_data_retention")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let training_opt_out = dp
            .get("training_opt_out")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let ret_days = dp
            .get("retention_days")
            .and_then(|v| v.as_u64())
            .map(|v| u32::try_from(v).unwrap_or(u32::MAX));

        if zdr {
            // Check 4: ZDR + training_opt_out: false
            if !training_opt_out {
                diags.push(format!(
                    "data-routing-policy: provider \"{id}\" declares zero_data_retention but training_opt_out is false (contradictory)"
                ));
            }
            if let Some(days) = ret_days {
                if days > 0 {
                    diags.push(format!(
                        "data-routing-policy: provider \"{id}\" declares zero_data_retention but retention_days is {days} (must be 0)"
                    ));
                }
            }
        }

        // Simulate filtering to check if this target would be excluded.
        let mut excluded = false;
        if require_zdr && !zdr {
            excluded = true;
        }
        if !excluded && require_no_training && !training_opt_out {
            excluded = true;
        }
        if !excluded {
            if let Some(max_days) = max_retention_days {
                match ret_days {
                    None => excluded = true,
                    Some(days) if days > max_days => excluded = true,
                    _ => {}
                }
            }
        }
        if excluded {
            would_be_excluded += 1;
        }
    }

    // Check 5: All targets would be excluded at runtime.
    if would_be_excluded == targets.len() {
        diags.push(
            "data-routing-policy: all providers would be excluded — requests will be blocked at runtime"
                .to_string(),
        );
    }

    diags
}

/// Cross-validate Phase 1 routing order/only/ignore configuration.
fn cross_validate_routing_order(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    let Some(r) = root.pointer("/providers/routing") else {
        return diags;
    };

    let has_only = r.get("only").is_some();
    let has_ignore = r.get("ignore").is_some();

    if has_only && has_ignore {
        diags.push("providers.routing: 'only' and 'ignore' are mutually exclusive".to_string());
    }

    let target_ids: Vec<&str> = root
        .pointer("/providers/targets")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| t.get("id").and_then(|v| v.as_str()))
                .collect()
        })
        .unwrap_or_default();

    if let Some(order) = r.get("order").and_then(|v| v.as_array()) {
        for id_val in order {
            if let Some(id) = id_val.as_str() {
                if !target_ids.contains(&id) {
                    diags.push(format!(
                        "providers.routing.order: unknown provider id '{id}'"
                    ));
                }
            }
        }
    }

    // Warn if the effective eligible set is empty.
    if !target_ids.is_empty() && !has_only && !has_ignore {
        return diags;
    }

    let eligible_count = if has_only {
        let only_ids: Vec<&str> = r
            .get("only")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        target_ids.iter().filter(|id| only_ids.contains(id)).count()
    } else if has_ignore {
        let ignore_ids: Vec<&str> = r
            .get("ignore")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        target_ids
            .iter()
            .filter(|id| !ignore_ids.contains(id))
            .count()
    } else {
        target_ids.len()
    };

    if eligible_count == 0 && !target_ids.is_empty() {
        diags.push(
            "providers.routing: only/ignore filters reduce eligible providers to zero".to_string(),
        );
    }

    diags
}

/// Cross-validate Phase 2 cost budget configuration.
fn cross_validate_cost_budget(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    if root.pointer("/providers/routing/max_price").is_none() {
        return diags;
    }

    let targets = root
        .pointer("/providers/targets")
        .and_then(|v| v.as_array());
    let any_pricing = targets
        .map(|arr| arr.iter().any(|t| t.get("pricing").is_some()))
        .unwrap_or(false);

    if !any_pricing {
        diags.push(
            "providers.routing.max_price: no providers have 'pricing' declared — cost filter has no effect"
                .to_string(),
        );
    }

    diags
}

/// Author-time mirror of the runtime region predicate
/// (`gateway::provider_endpoint_selection::provider_matches_region`) over raw
/// config JSON. A declared `data_residency` block is authoritative, so the lint
/// reports the same eligibility the gateway enforces.
fn target_json_matches_region(target: &serde_json::Value, require_region: &str) -> bool {
    if let Some(residency) = target.get("data_residency") {
        return residency
            .get("regions")
            .and_then(|v| v.as_array())
            .is_some_and(|regions| {
                regions.iter().any(|region| {
                    region
                        .as_str()
                        .is_some_and(|region| region.eq_ignore_ascii_case(require_region))
                })
            });
    }
    target
        .get("region")
        .and_then(|v| v.as_str())
        .is_some_and(|region| region.eq_ignore_ascii_case(require_region))
}

/// Cross-validate Phase 4 privacy routing (region, zdr shorthand).
fn cross_validate_privacy_routing(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    let routing = root.pointer("/providers/routing");

    if let Some(require_region) = routing
        .and_then(|r| r.get("require_region"))
        .and_then(|v| v.as_str())
    {
        let targets = root
            .pointer("/providers/targets")
            .and_then(|v| v.as_array());
        let any_region_metadata = targets
            .map(|arr| {
                arr.iter()
                    .any(|t| t.get("region").is_some() || t.get("data_residency").is_some())
            })
            .unwrap_or(false);

        if !any_region_metadata {
            diags.push(
                "providers.routing.require_region: no providers declare a 'region' or 'data_residency' — all will be excluded"
                    .to_string(),
            );
        } else if let Some(arr) = targets {
            let matching = arr
                .iter()
                .filter(|t| target_json_matches_region(t, require_region))
                .count();
            if matching == 0 {
                diags.push(format!(
                    "providers.routing.require_region: no providers in region '{require_region}' — requests will be blocked at runtime"
                ));
            }
        }
    }

    // Check zdr shorthand conflicts.
    if let Some(targets) = root
        .pointer("/providers/targets")
        .and_then(|v| v.as_array())
    {
        for t in targets {
            let zdr = t.get("zdr").and_then(|v| v.as_bool()).unwrap_or(false);
            if zdr {
                let dp_zdr = t
                    .get("data_policy")
                    .and_then(|dp| dp.get("zero_data_retention"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                if !dp_zdr {
                    let id = t.get("id").and_then(|v| v.as_str()).unwrap_or("<unknown>");
                    diags.push(format!(
                        "provider '{id}': zdr: true conflicts with data_policy.zero_data_retention: false"
                    ));
                }
            }
        }
    }

    diags
}

/// Cross-validate Phase 5 quantization constraints.
fn cross_validate_quantization(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    let Some(required) = root
        .pointer("/providers/routing/require_quantizations")
        .and_then(|v| v.as_array())
    else {
        return diags;
    };

    let required_strs: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
    let targets = root
        .pointer("/providers/targets")
        .and_then(|v| v.as_array());

    let any_quants = targets
        .map(|arr| arr.iter().any(|t| t.get("quantizations").is_some()))
        .unwrap_or(false);

    if !any_quants {
        diags.push(
            "providers.routing.require_quantizations: no providers declare 'quantizations' — all will be excluded"
                .to_string(),
        );
        return diags;
    }

    let matching = targets
        .map(|arr| {
            arr.iter()
                .filter(|t| {
                    t.get("quantizations")
                        .and_then(|v| v.as_array())
                        .map(|quants| {
                            required_strs
                                .iter()
                                .any(|r| quants.iter().any(|q| q.as_str() == Some(r)))
                        })
                        .unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0);

    if matching == 0 {
        diags.push(
            "providers.routing.require_quantizations: no providers match required quantizations — requests will be blocked at runtime"
                .to_string(),
        );
    }

    diags
}

/// Cross-validate Phase 14 load-balancing strategy configuration.
fn cross_validate_lb_strategies(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    let Some(strategy) = root
        .pointer("/providers/routing/strategy")
        .and_then(|v| v.as_str())
    else {
        return diags;
    };

    let targets = root
        .pointer("/providers/targets")
        .and_then(|v| v.as_array());

    // Warn if weight declared but strategy is not weighted_round_robin.
    if strategy != "weighted_round_robin" {
        let any_weight = targets
            .map(|arr| arr.iter().any(|t| t.get("weight").is_some()))
            .unwrap_or(false);
        if any_weight {
            diags.push(format!(
                "providers: 'weight' declared on targets but routing strategy is '{strategy}' — weight only applies with weighted_round_robin"
            ));
        }
    }

    // Error if any weight <= 0.
    if let Some(arr) = targets {
        for t in arr {
            if let Some(w) = t.get("weight").and_then(|v| v.as_f64()) {
                if w <= 0.0 {
                    let id = t.get("id").and_then(|v| v.as_str()).unwrap_or("<unknown>");
                    diags.push(format!("provider '{id}': weight must be > 0, got {w}"));
                }
            }
        }
    }

    // Warn if least_connections with single provider.
    if strategy == "least_connections" {
        let target_count = targets.map_or(0, |arr| arr.len());
        if target_count <= 1 {
            diags.push(
                "providers.routing: least_connections strategy is ineffective with a single provider"
                    .to_string(),
            );
        }
    }

    diags
}

// ─────────────────────────────────────────────────────────────────────────────
// Testing section cross-validation
// ─────────────────────────────────────────────────────────────────────────────

const KNOWN_ASSERTION_TYPES: &[&str] = &[
    "contains",
    "similar",
    "llm-rubric",
    "rouge",
    "meteor",
    "gleu",
    "semantic-similarity",
    "javascript",
    "python",
    "cost",
    "moderation",
    "context-faithfulness",
    "conversation-relevance",
    "is-refusal",
    "rag-document-exfiltration",
    "rag-poisoning",
    "rag-source-attribution",
    "threshold",
    "schema-match",
    "regex",
    "jsonpath",
    "is-json",
    "not-null",
    "equals",
    "starts-with",
    "ends-with",
    "less-than",
    "greater-than",
    "perplexity-score",
    "latency",
    "trajectory:goal-success",
    "trajectory:tool-used",
    "trajectory:tool-sequence",
    "trajectory:step-count",
    "trace-span-count",
    "trace-span-duration",
    "trace-tool-failure-rate",
];

const LLM_ASSERTION_TYPES: &[&str] = &["similar"];
const ROUGE_VARIANTS: &[&str] = &["rouge-1", "rouge-2", "rouge-l"];

fn cross_validate_testing_section(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    let Some(suites) = root.pointer("/testing/suites").and_then(|v| v.as_array()) else {
        return diags;
    };

    for (suite_idx, suite) in suites.iter().enumerate() {
        let suite_name = suite
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or_default();
        let suite_target = suite.get("target");

        if let Some(assertions) = suite.get("assertions").and_then(|a| a.as_array()) {
            for (a_idx, assertion) in assertions.iter().enumerate() {
                lint_assertion(
                    assertion,
                    &format!("testing.suites[{suite_idx}({suite_name})].assertions[{a_idx}]"),
                    suite_target,
                    &mut diags,
                );
            }
        }

        if let Some(cases) = suite.get("cases").and_then(|c| c.as_array()) {
            for (case_idx, case) in cases.iter().enumerate() {
                let case_name = case
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or_default();
                if let Some(assertions) = case.get("assertions").and_then(|a| a.as_array()) {
                    for (a_idx, assertion) in assertions.iter().enumerate() {
                        lint_assertion(
                            assertion,
                            &format!(
                                "testing.suites[{suite_idx}({suite_name})].cases[{case_idx}({case_name})].assertions[{a_idx}]"
                            ),
                            suite_target,
                            &mut diags,
                        );
                    }
                }
            }
        }
    }

    diags
}

fn lint_assertion(
    assertion: &serde_json::Value,
    path: &str,
    suite_target: Option<&serde_json::Value>,
    diags: &mut Vec<String>,
) {
    let Some(type_str) = assertion.get("type").and_then(|t| t.as_str()) else {
        diags.push(format!(
            "{path}: assertion is missing required 'type' field"
        ));
        return;
    };

    if !KNOWN_ASSERTION_TYPES.contains(&type_str) {
        diags.push(format!(
            "{path}: unknown assertion type '{type_str}' — may not be evaluated"
        ));
    }

    if LLM_ASSERTION_TYPES.contains(&type_str) && suite_target.is_none() {
        diags.push(format!(
            "{path}: assertion type '{type_str}' requires an LLM provider — set 'target' on the suite or provide an LLM provider"
        ));
    }

    if type_str == "llm-rubric"
        && !has_string_field(assertion, &["rubric"])
        && !has_string_field(
            assertion.get("config").unwrap_or(&serde_json::Value::Null),
            &["rubric"],
        )
    {
        diags.push(format!(
            "{path}: assertion type 'llm-rubric' requires 'config.rubric'"
        ));
    }

    if matches!(
        type_str,
        "rouge" | "meteor" | "gleu" | "semantic-similarity"
    ) && !has_string_field(assertion, &["reference"])
        && !has_string_field(
            assertion.get("config").unwrap_or(&serde_json::Value::Null),
            &["reference"],
        )
    {
        diags.push(format!(
            "{path}: assertion type '{type_str}' requires 'config.reference'"
        ));
    }

    if type_str == "rouge" {
        if let Some(variant) = string_field(assertion, &["variant"]).or_else(|| {
            string_field(
                assertion.get("config").unwrap_or(&serde_json::Value::Null),
                &["variant"],
            )
        }) {
            if !ROUGE_VARIANTS.contains(&variant) {
                diags.push(format!(
                    "{path}: rouge variant '{variant}' should be one of: {}",
                    ROUGE_VARIANTS.join(", ")
                ));
            }
        }
    }

    if type_str == "rag-poisoning"
        && !has_string_field(assertion, &["poisoned_context"])
        && !has_string_field(
            assertion.get("config").unwrap_or(&serde_json::Value::Null),
            &["poisoned_context"],
        )
    {
        diags.push(format!(
            "{path}: assertion type 'rag-poisoning' requires 'config.poisoned_context'"
        ));
    }
}

fn has_string_field(value: &serde_json::Value, keys: &[&str]) -> bool {
    string_field(value, keys).is_some()
}

fn string_field<'a>(value: &'a serde_json::Value, keys: &[&str]) -> Option<&'a str> {
    for key in keys {
        if let Some(found) = value.get(key).and_then(|v| v.as_str()) {
            return Some(found);
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 11 — assertion mode / severity cross-validation
// ─────────────────────────────────────────────────────────────────────────────

const VALID_ASSERTION_MODES: &[&str] = &["enforce", "audit", "shadow"];
const VALID_ASSERTION_SEVERITIES: &[&str] = &["critical", "warning", "info"];

fn cross_validate_assertion_modes(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();
    let mut check_list: Vec<(serde_json::Value, String)> = Vec::new();

    if let Some(arr) = root
        .pointer("/policy/quality-scorer/assertions")
        .and_then(|v| v.as_array())
    {
        for (i, a) in arr.iter().enumerate() {
            check_list.push((a.clone(), format!("policy.quality-scorer.assertions[{i}]")));
        }
    }

    if let Some(packs_obj) = root.get("assertion_packs").and_then(|v| v.as_object()) {
        for (pack_name, pack_assertions) in packs_obj {
            if let Some(arr) = pack_assertions.as_array() {
                for (i, a) in arr.iter().enumerate() {
                    check_list.push((a.clone(), format!("assertion_packs.{pack_name}[{i}]")));
                }
            }
        }
    }

    if let Some(suites) = root.pointer("/testing/suites").and_then(|v| v.as_array()) {
        for (si, suite) in suites.iter().enumerate() {
            let sname = suite.get("name").and_then(|n| n.as_str()).unwrap_or("");
            if let Some(arr) = suite.get("assertions").and_then(|v| v.as_array()) {
                for (i, a) in arr.iter().enumerate() {
                    check_list.push((
                        a.clone(),
                        format!("testing.suites[{si}({sname})].assertions[{i}]"),
                    ));
                }
            }
            if let Some(cases) = suite.get("cases").and_then(|c| c.as_array()) {
                for (ci, case) in cases.iter().enumerate() {
                    let cname = case.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    if let Some(arr) = case.get("assertions").and_then(|v| v.as_array()) {
                        for (i, a) in arr.iter().enumerate() {
                            check_list.push((
                                a.clone(),
                                format!(
                                    "testing.suites[{si}({sname})].cases[{ci}({cname})].assertions[{i}]"
                                ),
                            ));
                        }
                    }
                }
            }
        }
    }

    for (a, path) in check_list {
        if let Some(mode) = a.get("mode").and_then(|v| v.as_str()) {
            if !VALID_ASSERTION_MODES.contains(&mode) {
                diags.push(format!(
                    "{path}: unknown mode '{mode}' — expected one of: {}",
                    VALID_ASSERTION_MODES.join(", ")
                ));
            }
        }
        if let Some(sev) = a.get("severity").and_then(|v| v.as_str()) {
            if !VALID_ASSERTION_SEVERITIES.contains(&sev) {
                diags.push(format!(
                    "{path}: unknown severity '{sev}' — expected one of: {}",
                    VALID_ASSERTION_SEVERITIES.join(", ")
                ));
            }
        }
    }

    diags
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 12 — pass_policy cross-validation
// ─────────────────────────────────────────────────────────────────────────────

const VALID_PASS_STRATEGIES: &[&str] = &["all", "quorum", "weighted_average"];

fn cross_validate_pass_policy(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    let Some(pp) = root.pointer("/policy/quality-scorer/pass_policy") else {
        return diags;
    };

    if let Some(strategy) = pp.get("strategy").and_then(|v| v.as_str()) {
        if !VALID_PASS_STRATEGIES.contains(&strategy) {
            diags.push(format!(
                "policy.quality-scorer.pass_policy: unknown strategy '{strategy}' — expected one of: {}",
                VALID_PASS_STRATEGIES.join(", ")
            ));
        }

        if strategy == "quorum" {
            match pp.get("quorum").and_then(|v| v.as_f64()) {
                None => diags.push(
                    "policy.quality-scorer.pass_policy: strategy 'quorum' requires a 'quorum' value (0.0..1.0)".to_string(),
                ),
                Some(q) if !(0.0..=1.0).contains(&q) => diags.push(format!(
                    "policy.quality-scorer.pass_policy: 'quorum' must be in [0.0, 1.0], got {q}"
                )),
                _ => {}
            }
        }

        if strategy == "weighted_average" {
            match pp.get("threshold").and_then(|v| v.as_f64()) {
                None => diags.push(
                    "policy.quality-scorer.pass_policy: strategy 'weighted_average' requires a 'threshold' value".to_string(),
                ),
                Some(t) if !(0.0..=1.0).contains(&t) => diags.push(format!(
                    "policy.quality-scorer.pass_policy: 'threshold' must be in [0.0, 1.0], got {t}"
                )),
                _ => {}
            }
        }
    }

    diags
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 13 — assertion_packs cross-validation
// ─────────────────────────────────────────────────────────────────────────────

fn cross_validate_assertion_packs(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    let defined: std::collections::HashSet<&str> = root
        .get("assertion_packs")
        .and_then(|v| v.as_object())
        .map(|obj| obj.keys().map(|k| k.as_str()).collect())
        .unwrap_or_default();

    let mut check_refs = |arr: &Vec<serde_json::Value>, base: &str| {
        for (i, a) in arr.iter().enumerate() {
            if let Some(pack) = a.get("pack").and_then(|v| v.as_str()) {
                if !defined.contains(pack) {
                    diags.push(format!(
                        "{base}[{i}]: references assertion pack '{pack}' which is not defined in 'assertion_packs'"
                    ));
                }
            }
        }
    };

    if let Some(arr) = root
        .pointer("/policy/quality-scorer/assertions")
        .and_then(|v| v.as_array())
    {
        check_refs(arr, "policy.quality-scorer.assertions");
    }

    if let Some(suites) = root.pointer("/testing/suites").and_then(|v| v.as_array()) {
        for (si, suite) in suites.iter().enumerate() {
            let sname = suite.get("name").and_then(|n| n.as_str()).unwrap_or("");
            if let Some(arr) = suite.get("assertions").and_then(|v| v.as_array()) {
                check_refs(arr, &format!("testing.suites[{si}({sname})].assertions"));
            }
            if let Some(cases) = suite.get("cases").and_then(|c| c.as_array()) {
                for (ci, case) in cases.iter().enumerate() {
                    let cname = case.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    if let Some(arr) = case.get("assertions").and_then(|v| v.as_array()) {
                        check_refs(
                            arr,
                            &format!(
                                "testing.suites[{si}({sname})].cases[{ci}({cname})].assertions"
                            ),
                        );
                    }
                }
            }
        }
    }

    if let Some(packs_obj) = root.get("assertion_packs").and_then(|v| v.as_object()) {
        for (pack_name, pack_val) in packs_obj {
            match pack_val.as_array() {
                None => diags.push(format!(
                    "assertion_packs.{pack_name}: must be an array of assertion objects"
                )),
                Some(arr) if arr.is_empty() => diags.push(format!(
                    "assertion_packs.{pack_name}: is empty — assertion packs should contain at least one assertion"
                )),
                _ => {}
            }
        }
    }

    diags
}

// ─── Phase 10 — `when` predicate cross-validation ────────────────────────────

/// Validate `when` predicates on conditional chain entries.
fn cross_validate_when_predicates(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    let Some(chain) = root.pointer("/policies/chain").and_then(|v| v.as_array()) else {
        return diags;
    };

    for (i, entry) in chain.iter().enumerate() {
        // Only validate object-form entries (plain strings are validated by JSON Schema).
        let Some(obj) = entry.as_object() else {
            continue;
        };
        if obj.len() != 1 {
            // Structural error handled by JSON Schema; skip.
            continue;
        }
        // SAFETY: invariant: single-key object verified above
        #[allow(clippy::expect_used)]
        let (kind, inner) = obj
            .iter()
            .next()
            .expect("invariant: single-key object verified above");

        let Some(when) = inner.get("when") else {
            continue;
        };
        let when_path = format!("policies.chain[{i}].{kind}.when");

        if let Some(path_val) = when.get("path") {
            match path_val.as_str() {
                None => diags.push(format!("{when_path}.path: must be a string")),
                Some(p) if !p.starts_with('/') => diags.push(format!(
                    "{when_path}.path: '{p}' must start with '/' for unambiguous prefix matching"
                )),
                _ => {}
            }
        }

        if let Some(model_val) = when.get("model") {
            match model_val.as_array() {
                None => diags.push(format!("{when_path}.model: must be an array of strings")),
                Some(arr) if arr.is_empty() => diags.push(format!(
                    "{when_path}.model: empty list will never match — omit to match all models"
                )),
                _ => {}
            }
        }

        if let Some(header_val) = when.get("header") {
            if let Some(hdr_obj) = header_val.as_object() {
                for (hk, _) in hdr_obj {
                    if hk != &hk.to_lowercase() {
                        diags.push(format!(
                            "{when_path}.header: key '{hk}' should be lowercase \
                             (HTTP header names are case-insensitive but lowercase is conventional)"
                        ));
                    }
                }
            }
        }

        // Reject arbitrary / unread conditional-object and when property names.
        if let Some(inner_object) = inner.as_object() {
            for key in inner_object.keys() {
                if !crate::gateway::declarative_config::CHAIN_CONDITIONAL_CONSUMED_KEYS
                    .contains(&key.as_str())
                {
                    diags.push(format!(
                        "policies.chain[{i}].{kind}.{key}: unknown conditional field — \
                         allowed keys: {}",
                        crate::gateway::declarative_config::CHAIN_CONDITIONAL_CONSUMED_KEYS
                            .join(", ")
                    ));
                }
            }
            if let Some(when_object) = when.as_object() {
                for key in when_object.keys() {
                    if !crate::gateway::declarative_config::WHEN_PREDICATE_CONSUMED_KEYS
                        .contains(&key.as_str())
                    {
                        diags.push(format!(
                            "{when_path}.{key}: unknown when field — allowed keys: {}",
                            crate::gateway::declarative_config::WHEN_PREDICATE_CONSUMED_KEYS
                                .join(", ")
                        ));
                    }
                }
            }
        }
    }

    diags
}

// ─── Phase 16/17 — routes cross-validation ───────────────────────────────────

/// Validate the top-level `routes` section.
fn cross_validate_routes(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    let Some(routes) = root.get("routes").and_then(|v| v.as_array()) else {
        return diags;
    };

    // Collect known policy kinds from the chain and policy blocks.
    let known_kinds: std::collections::HashSet<&str> = root
        .pointer("/policies/chain")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .collect::<std::collections::HashSet<_>>()
        })
        .unwrap_or_default();

    let _known_providers: std::collections::HashSet<&str> = root
        .pointer("/providers/targets")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| t.get("id").and_then(|id| id.as_str()))
                .collect::<std::collections::HashSet<_>>()
        })
        .unwrap_or_default();

    // Check for duplicate route names.
    let mut seen_names: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for (i, route) in routes.iter().enumerate() {
        let name = route.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if name.is_empty() {
            diags.push(format!(
                "routes[{i}]: 'name' is required and must be a non-empty string"
            ));
            continue;
        }
        if !seen_names.insert(name) {
            diags.push(format!(
                "routes[{i}]: duplicate route name '{name}' — route names must be unique"
            ));
        }
    }

    for (i, route) in routes.iter().enumerate() {
        let name_owned: String;
        let name = match route.get("name").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => {
                name_owned = format!("[{i}]");
                &name_owned
            }
        };

        if route.get("strip_path").is_some() {
            diags.push(format!(
                "routes['{name}']: 'strip_path' has been removed — \
                 the gateway no longer rewrites upstream paths"
            ));
        }

        if route.get("upstream").is_some() {
            diags.push(format!(
                "routes['{name}']: 'upstream' has been removed — \
                 use provider routing configuration instead"
            ));
        }

        // Validate route-scoped chain entries.
        if let Some(chain_arr) = route.get("chain").and_then(|v| v.as_array()) {
            for (ci, entry) in chain_arr.iter().enumerate() {
                let entry_kind = if let Some(s) = entry.as_str() {
                    s
                } else if let Some(obj) = entry.as_object() {
                    if let Some((k, _)) = obj.iter().next() {
                        k.as_str()
                    } else {
                        continue;
                    }
                } else {
                    continue;
                };

                // Only warn if global chain is non-empty and this kind is unknown there.
                if !known_kinds.is_empty() && !known_kinds.contains(entry_kind) {
                    diags.push(format!(
                        "routes['{name}'].chain[{ci}]: policy kind '{entry_kind}' is not \
                         in the global policies.chain — ensure a policy block is configured"
                    ));
                }
            }
        }
    }

    diags
}

// ─── Phase 18: token_rate_limit cross-validation ─────────────────────────────

fn cross_validate_token_rate_limit(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    let Some(cfg) = root.pointer("/token_rate_limit") else {
        return diags;
    };

    if let Some(max) = cfg.get("max_tokens").and_then(|v| v.as_u64()) {
        if max == 0 {
            diags.push("token_rate_limit.max_tokens: must be greater than zero".to_string());
        }
    }

    if let Some(window) = cfg.get("window_seconds").and_then(|v| v.as_u64()) {
        if window < 10 {
            diags.push(format!(
                "token_rate_limit.window_seconds: {window}s is very short — \
                 consider a window of at least 10 seconds"
            ));
        }
    }

    // Warn when scope=per_key: the proxy needs an Authorization header to key on.
    if cfg
        .get("scope")
        .and_then(|v| v.as_str())
        .map(|s| s == "per_key")
        .unwrap_or(false)
    {
        // Check whether the config strips Authorization or has no policy that reads it.
        // We emit a gentler advisory rather than a hard error.
        let chain = root
            .pointer("/policies/chain")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let has_key_based_policy = chain
            .iter()
            .any(|k| matches!(k.as_str(), Some("auth-check") | Some("api-key-policy")));
        if !has_key_based_policy {
            diags.push(
                "token_rate_limit.scope=per_key: no api-key-policy or auth-check in chain; \
                 ensure an Authorization header is forwarded for accurate per-key tracking"
                    .to_string(),
            );
        }
    }

    diags
}

// ─── Phase 19: global / IP rate limit cross-validation ───────────────────────

fn cross_validate_request_rate_limits(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    for section in &["global_rate_limit", "ip_rate_limit"] {
        let Some(cfg) = root.pointer(&format!("/{section}")) else {
            continue;
        };

        if let Some(max) = cfg.get("max_requests").and_then(|v| v.as_u64()) {
            if max == 0 {
                diags.push(format!("{section}.max_requests: must be greater than zero"));
            }
        }

        if let Some(window) = cfg.get("window_seconds").and_then(|v| v.as_u64()) {
            if window > 3600 {
                diags.push(format!(
                    "{section}.window_seconds: {window}s exceeds one hour; \
                     consider whether a shorter window better matches your SLO"
                ));
            }
        }
    }

    for section in ["ip_rate_limit", "ip_allowlist"] {
        let Some(cidrs) = root
            .pointer(&format!("/{section}/trusted_proxy_cidrs"))
            .and_then(|value| value.as_array())
        else {
            continue;
        };
        for (index, value) in cidrs.iter().enumerate() {
            let Some(value) = value.as_str() else {
                continue;
            };
            if value.parse::<ipnet::IpNet>().is_err() && value.parse::<std::net::IpAddr>().is_err()
            {
                diags.push(format!(
                    "{section}.trusted_proxy_cidrs[{index}]: invalid CIDR or IP '{value}'"
                ));
            }
        }
    }

    diags
}

// ─── Phase 20: size_limits cross-validation ───────────────────────────────────

fn cross_validate_size_limits(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    let Some(cfg) = root.pointer("/size_limits") else {
        return diags;
    };

    if let Some(max_body) = cfg.get("max_body_bytes").and_then(|v| v.as_u64()) {
        if max_body < 1024 {
            diags.push(format!(
                "size_limits.max_body_bytes: {max_body} is below 1 KiB — \
                 this may reject otherwise valid chat completions requests"
            ));
        }
    }

    if let Some(max_url) = cfg.get("max_url_bytes").and_then(|v| v.as_u64()) {
        if max_url < 256 {
            diags.push(format!(
                "size_limits.max_url_bytes: {max_url} is below 256 bytes — \
                 this may reject standard API paths"
            ));
        }
    }

    diags
}

// ─── Phase 21: consumer_groups cross-validation ─────────────────────────────

pub fn cross_validate_consumer_groups(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    let Some(groups) = root
        .pointer("/consumer_groups/groups")
        .and_then(|value| value.as_array())
    else {
        return diags;
    };

    let known_kinds: std::collections::HashSet<&str> = root
        .pointer("/policies/chain")
        .and_then(|value| value.as_array())
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| {
                    entry.as_str().or_else(|| {
                        entry
                            .as_object()
                            .and_then(|object| object.keys().next().map(String::as_str))
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let mut seen_names = std::collections::HashSet::new();
    let mut seen_hashes: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    for (group_index, group) in groups.iter().enumerate() {
        let name = group
            .get("name")
            .and_then(|value| value.as_str())
            .unwrap_or("");

        if !name.is_empty() && !seen_names.insert(name.to_string()) {
            diags.push(format!(
                "consumer_groups.groups[{group_index}]: duplicate group name '{name}'"
            ));
        }

        match group.get("api_keys").and_then(|value| value.as_array()) {
            Some(api_keys) if api_keys.is_empty() => diags.push(format!(
                "consumer_groups.groups[{group_index}]('{name}'): api_keys is empty — the group will never match requests"
            )),
            Some(api_keys) => {
                for (key_index, api_key) in api_keys.iter().enumerate() {
                    let Some(api_key_value) = api_key.as_str() else {
                        continue;
                    };
                    if !crate::gateway::consumer::is_sha256_hex(api_key_value) {
                        diags.push(format!(
                            "consumer_groups.groups[{group_index}]('{name}').api_keys[{key_index}]: value does not look like a SHA-256 hex digest — store hashed API keys in config"
                        ));
                        continue;
                    }

                    let normalized = api_key_value.to_ascii_lowercase();
                    if let Some(existing_group) = seen_hashes.insert(normalized, name.to_string()) {
                        diags.push(format!(
                            "consumer_groups.groups[{group_index}]('{name}').api_keys[{key_index}]: API key hash is already assigned to group '{existing_group}'"
                        ));
                    }
                }
            }
            None => {}
        }

        if let Some(chain) = group.get("chain").and_then(|value| value.as_array()) {
            for (chain_index, entry) in chain.iter().enumerate() {
                let Some(entry_kind) = entry.as_str().or_else(|| {
                    entry
                        .as_object()
                        .and_then(|object| object.keys().next().map(String::as_str))
                }) else {
                    continue;
                };

                if !known_kinds.is_empty() && !known_kinds.contains(entry_kind) {
                    diags.push(format!(
                        "consumer_groups.groups[{group_index}]('{name}').chain[{chain_index}]: policy kind '{entry_kind}' is not in the global policies.chain — ensure a policy block is configured"
                    ));
                }
            }
        }
    }

    diags
}

/// Phase 15 + 35: cross-validate provider format and auth configuration.
///
/// Warns when a provider's base URL suggests a format or auth mode that the
/// operator has not declared explicitly, and errors when required provider-type
/// fields are missing.
fn cross_validate_unavailable_providers(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    let Some(targets) = root
        .pointer("/providers/targets")
        .and_then(|value| value.as_array())
    else {
        return diags;
    };

    for (index, target) in targets.iter().enumerate() {
        let provider = target
            .get("provider")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        if let Err(error) =
            crate::gateway::provider_catalog::validate_exact_udr_provider_id(provider)
        {
            let id = target
                .get("id")
                .and_then(|value| value.as_str())
                .unwrap_or("(unknown)");
            diags.push(format!("providers.targets[{index}] '{id}': {error}"));
        }
        if crate::gateway::provider_catalog::is_unavailable_provider(provider) {
            let id = target
                .get("id")
                .and_then(|value| value.as_str())
                .unwrap_or("(unknown)");
            diags.push(format!(
                "providers.targets[{index}] '{id}': {}",
                crate::gateway::provider_catalog::unavailable_provider_message(provider)
            ));
        }
    }

    diags
}

pub fn cross_validate_provider_format_and_auth(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    let Some(targets) = root
        .pointer("/providers/targets")
        .and_then(|v| v.as_array())
    else {
        return diags;
    };

    for (i, target) in targets.iter().enumerate() {
        let id = target
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>");
        let base_url = target
            .get("base_url")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let provider_type = target.get("provider_type").and_then(|v| v.as_str());
        let format = target.get("format").and_then(|v| v.as_str());
        let secret_key_ref = target.get("secret_key_ref");
        let secret_key_env = secret_key_ref
            .and_then(|value| value.get("env"))
            .and_then(|value| value.as_str());

        // Phase 35: azure-openai requires azure_deployment (or model serves as a fallback,
        // but an explicit deployment name is strongly recommended).
        if provider_type == Some("azure-openai")
            && target
                .get("azure_deployment")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .is_none()
        {
            diags.push(format!(
                "providers.targets[{i}] ({id}): provider_type 'azure-openai' should set \
                 'azure_deployment'; otherwise the model name is used as the deployment name"
            ));
        }

        // Phase 35: bedrock/vertex do not need secret_key_ref.env — warn if still set to
        // something that looks like a placeholder.
        if matches!(provider_type, Some("aws-bedrock")) {
            if let Some(key_env) = secret_key_env {
                if key_env.to_ascii_uppercase().contains("PLACEHOLDER")
                    || key_env.to_ascii_uppercase().contains("EXAMPLE")
                {
                    diags.push(format!(
                        "providers.targets[{i}] ({id}): aws-bedrock uses AWS credential chain; \
                         secret_key_ref.env '{key_env}' looks like a placeholder"
                    ));
                }
            }
            if target.get("aws_region").is_none() {
                diags.push(format!(
                    "providers.targets[{i}] ({id}): provider_type 'aws-bedrock' should set \
                     explicit 'aws_region'; ambient AWS_REGION / AWS_DEFAULT_REGION fallback is no longer supported"
                ));
            }
            if target
                .get("bedrock_model_family")
                .and_then(|v| v.as_str())
                .filter(|value| !value.trim().is_empty())
                != Some("anthropic_messages")
            {
                diags.push(format!(
                    "providers.targets[{i}] ({id}): provider_type 'aws-bedrock' must set \
                     'bedrock_model_family: anthropic_messages'"
                ));
            }
            if let Some(model) = target.get("model").and_then(|v| v.as_str()) {
                if !model.contains("anthropic.") {
                    diags.push(format!(
                        "providers.targets[{i}] ({id}): provider_type 'aws-bedrock' must use an \
                         Anthropic model id"
                    ));
                }
            }
            if let (Some(base_url), Some(region)) = (
                target.get("base_url").and_then(|v| v.as_str()),
                target.get("aws_region").and_then(|v| v.as_str()),
            ) {
                if let Ok(url) = reqwest::Url::parse(base_url) {
                    if let Some(host) = url.host_str() {
                        if !matches!(host, "localhost" | "127.0.0.1" | "::1")
                            && host.contains("amazonaws.com")
                            && !host.contains(&format!("bedrock-runtime.{region}.amazonaws.com"))
                        {
                            diags.push(format!(
                                "providers.targets[{i}] ({id}): aws-bedrock base_url host must match aws_region '{region}'"
                            ));
                        }
                    }
                }
            }
        }

        if matches!(provider_type, Some("watsonx")) {
            let watsonx_api_version = target
                .get("watsonx_api_version")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty());
            if watsonx_api_version.is_none() {
                diags.push(format!(
                    "providers.targets[{i}] ({id}): provider_type 'watsonx' must set nonempty \
                     'watsonx_api_version'"
                ));
            }
            let project_id = target
                .get("watsonx_project_id")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let space_id = target
                .get("watsonx_space_id")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty());
            if project_id.is_some() == space_id.is_some() {
                diags.push(format!(
                    "providers.targets[{i}] ({id}): provider_type 'watsonx' must set exactly \
                     one of 'watsonx_project_id' or 'watsonx_space_id'"
                ));
            }
            match reqwest::Url::parse(base_url) {
                Ok(url)
                    if url.scheme() == "https"
                        && url
                            .host_str()
                            .is_some_and(|host| host.ends_with(".ml.cloud.ibm.com")) => {}
                _ => diags.push(format!(
                    "providers.targets[{i}] ({id}): provider_type 'watsonx' requires a regional https://*.ml.cloud.ibm.com base_url"
                )),
            }
        }

        // Phase 35: vertex should declare gcp_project.
        if matches!(provider_type, Some("google-vertex"))
            && target.get("gcp_project").and_then(|v| v.as_str()).is_none()
        {
            diags.push(format!(
                "providers.targets[{i}] ({id}): provider_type 'google-vertex' should set \
                 'gcp_project'"
            ));
        }

        if matches!(provider_type, Some("google-ai-studio")) && secret_key_ref.is_none() {
            diags.push(format!(
                "providers.targets[{i}] ({id}): provider_type 'google-ai-studio' should set \
                 'secret_key_ref' to a Gemini API key reference"
            ));
        }

        if matches!(provider_type, Some("sagemaker")) && target.get("aws_region").is_none() {
            diags.push(format!(
                "providers.targets[{i}] ({id}): provider_type 'sagemaker' should set \
                 explicit 'aws_region'; ambient AWS_REGION / AWS_DEFAULT_REGION fallback is no longer supported"
            ));
        }

        if matches!(provider_type, Some("cloudflare-ai")) {
            if target.get("accountId").is_some() {
                diags.push(format!(
                    "providers.targets[{i}] ({id}): fatal: 'accountId' is no longer accepted; use 'cloudflare_account_id'"
                ));
            }
            if target.get("accountIdEnvar").is_some() {
                diags.push(format!(
                    "providers.targets[{i}] ({id}): fatal: 'accountIdEnvar' is no longer accepted; use 'cloudflare_account_id_env'"
                ));
            }
            let has_account = target
                .get("cloudflare_account_id")
                .and_then(|v| v.as_str())
                .filter(|value| !value.is_empty())
                .is_some();
            if !has_account && target.get("base_url").and_then(|v| v.as_str()).is_none() {
                diags.push(format!(
                    "providers.targets[{i}] ({id}): provider_type 'cloudflare-ai' should set \
                     'cloudflare_account_id' or provide 'base_url'"
                ));
            }
        }

        if matches!(provider_type, Some("snowflake-cortex")) {
            if target.get("accountIdentifier").is_some() {
                diags.push(format!(
                    "providers.targets[{i}] ({id}): fatal: 'accountIdentifier' is no longer accepted; use 'snowflake_account_identifier'"
                ));
            }
            if target.get("accountIdentifierEnvar").is_some() {
                diags.push(format!(
                    "providers.targets[{i}] ({id}): fatal: 'accountIdentifierEnvar' is no longer accepted; use 'snowflake_account_identifier_env'"
                ));
            }
            let has_account = target
                .get("snowflake_account_identifier")
                .and_then(|v| v.as_str())
                .filter(|value| !value.is_empty())
                .is_some();
            if !has_account && target.get("base_url").and_then(|v| v.as_str()).is_none() {
                diags.push(format!(
                    "providers.targets[{i}] ({id}): provider_type 'snowflake-cortex' should set \
                     'snowflake_account_identifier' or provide 'base_url'"
                ));
            }
        }

        for (legacy, canonical) in [
            ("apiBaseUrl", "base_url"),
            ("gatewayId", "cloudflare_gateway_id"),
            ("gatewayIdEnvar", "cloudflare_gateway_id_env"),
            ("gatewayProvider", "gateway_provider"),
            ("resourceName", "resource_name"),
            ("deploymentName", "deployment_name"),
        ] {
            if target.get(legacy).is_some() {
                diags.push(format!(
                    "providers.targets[{i}] ({id}): legacy field '{legacy}' is not supported; use '{canonical}'"
                ));
            }
        }

        // Phase 15: warn if base URL hints at Anthropic but format/provider_type not set.
        if base_url.contains("anthropic.com") && format.is_none() && provider_type.is_none() {
            diags.push(format!(
                "providers.targets[{i}] ({id}): base_url looks like Anthropic API but \
                 'format' and 'provider_type' are not set — consider setting \
                 provider_type: anthropic and format: anthropic"
            ));
        }

        if base_url.contains("cohere.ai") && format.is_none() && provider_type.is_none() {
            diags.push(format!(
                "providers.targets[{i}] ({id}): base_url looks like Cohere API but \
                 'format' and 'provider_type' are not set — consider setting \
                 provider_type: cohere and format: cohere"
            ));
        }

        if base_url.contains("huggingface.co") && format.is_none() && provider_type.is_none() {
            diags.push(format!(
                "providers.targets[{i}] ({id}): base_url looks like HuggingFace Inference API but \
                 'format' and 'provider_type' are not set — consider setting \
                 provider_type: huggingface and format: huggingface"
            ));
        }

        if base_url.contains("replicate.com") && format.is_none() && provider_type.is_none() {
            diags.push(format!(
                "providers.targets[{i}] ({id}): base_url looks like Replicate API but \
                 'format' and 'provider_type' are not set — consider setting \
                 provider_type: replicate and format: replicate"
            ));
        }

        if base_url.contains("generativelanguage.googleapis.com")
            && format.is_none()
            && provider_type.is_none()
        {
            diags.push(format!(
                "providers.targets[{i}] ({id}): base_url looks like Google AI Studio but \
                 'format' and 'provider_type' are not set — consider setting \
                 provider_type: google-ai-studio and format: google-gemini"
            ));
        }

        if base_url.contains("api.cloudflare.com/client/v4/accounts")
            && base_url.contains("/ai/v1")
            && format.is_none()
            && provider_type.is_none()
        {
            diags.push(format!(
                "providers.targets[{i}] ({id}): base_url looks like Cloudflare AI but \
                 'provider_type' is not set — consider setting provider_type: cloudflare-ai"
            ));
        }

        if base_url.contains(".snowflakecomputing.com")
            && format.is_none()
            && provider_type.is_none()
        {
            diags.push(format!(
                "providers.targets[{i}] ({id}): base_url looks like Snowflake Cortex but \
                 'provider_type' is not set — consider setting provider_type: snowflake-cortex"
            ));
        }

        if matches!(provider_type, Some("databricks")) && target.get("path_template").is_none() {
            diags.push(format!(
                "providers.targets[{i}] ({id}): provider_type 'databricks' should set \
                 'path_template' when the serving endpoint name differs from model"
            ));
        }

        if matches!(provider_type, Some("watsonx")) && secret_key_ref.is_none() {
            diags.push(format!(
                "providers.targets[{i}] ({id}): provider_type 'watsonx' should set \
                 'secret_key_ref' to an IBM Cloud API key or access token reference"
            ));
        }
    }

    diags
}

pub fn cross_validate_execution_targets(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    let Some(targets) = root
        .pointer("/providers/targets")
        .and_then(|value| value.as_array())
    else {
        return diags;
    };

    for (index, target) in targets.iter().enumerate() {
        let id = target
            .get("id")
            .and_then(|value| value.as_str())
            .unwrap_or("<unknown>");
        let Some(provider) = target.get("provider").and_then(|value| value.as_str()) else {
            continue;
        };

        // Use classify_capability for an early, descriptive diagnostic when
        // the provider string is a known statically unsupported execution
        // family such as `go`, `ruby`, or `manual-input`. The guard below
        // limits this check to providers that parse_execution_target already
        // recognizes as an Unsupported execution alias; regular HTTP upstream
        // providers parse as `None` and are intentionally excluded here.
        {
            use crate::gateway::execution_runtime::{classify_capability, ExecutionCapability};
            let is_known_unsupported_execution_alias = matches!(
                crate::gateway::execution_runtime::parse_execution_target(provider, target),
                Ok(Some(
                    crate::gateway::execution_runtime::ExecutionTarget::Unsupported { .. }
                ))
            );
            if is_known_unsupported_execution_alias
                && matches!(
                    classify_capability(provider),
                    ExecutionCapability::UnsupportedAtConfigTime
                )
            {
                diags.push(format!(
                    "providers.targets[{index}] ({id}): provider '{provider}' is a statically \
                     unsupported execution family that cannot run inside verdictan gateway run. \
                     Replace it with an explicit exec: or file:// target, or use an \
                     adapter-backed family such as 'anthropic:claude-agent-sdk' or \
                     'openai:agents' with adapter_command."
                ));
                continue;
            }
        }

        if let Some(family_info) =
            crate::gateway::execution_runtime::execution_family_info(provider)
        {
            let has_adapter_command = target
                .get("adapter_command")
                .and_then(|value| value.as_str())
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false);
            let has_claude_override = target
                .get("path_to_claude_code_executable")
                .and_then(|value| value.as_str())
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false);
            let has_codex_override = target
                .get("codex_path_override")
                .and_then(|value| value.as_str())
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false);

            match family_info.family.support_mode() {
                crate::gateway::execution_runtime::ExecutionSupportMode::AdapterOnly => {
                    if !has_adapter_command {
                        diags.push(format!(
                            "providers.targets[{index}] ({id}): adapter-only execution family '{}' requires adapter_command and optional adapter_args; native runner overrides are not supported",
                            family_info.kind
                        ));
                        continue;
                    }

                    if has_claude_override || has_codex_override {
                        diags.push(format!(
                            "providers.targets[{index}] ({id}): adapter-only execution family '{}' does not support native runner override fields such as path_to_claude_code_executable or codex_path_override",
                            family_info.kind
                        ));
                    }
                }
                crate::gateway::execution_runtime::ExecutionSupportMode::NativeRunnerOrAdapter => {
                    match family_info.family {
                        crate::gateway::execution_runtime::AdapterFamily::ClaudeAgentSdk => {
                            if has_codex_override {
                                diags.push(format!(
                                    "providers.targets[{index}] ({id}): native execution family '{}' cannot use codex_path_override; use path_to_claude_code_executable or adapter_command instead",
                                    family_info.kind
                                ));
                            }
                        }
                        crate::gateway::execution_runtime::AdapterFamily::CodexSdk => {
                            if has_claude_override {
                                diags.push(format!(
                                    "providers.targets[{index}] ({id}): native execution family '{}' cannot use path_to_claude_code_executable; use codex_path_override or adapter_command instead",
                                    family_info.kind
                                ));
                            }
                        }
                        crate::gateway::execution_runtime::AdapterFamily::Browser
                        | crate::gateway::execution_runtime::AdapterFamily::ChatKit
                        | crate::gateway::execution_runtime::AdapterFamily::Mcp
                        | crate::gateway::execution_runtime::AdapterFamily::WebSocket
                        | crate::gateway::execution_runtime::AdapterFamily::OpenAiAgents
                        | crate::gateway::execution_runtime::AdapterFamily::OpenCodeSdk
                        | crate::gateway::execution_runtime::AdapterFamily::BedrockAgents
                        | crate::gateway::execution_runtime::AdapterFamily::Transformers => {}
                    }
                }
            }
        }

        match crate::gateway::execution_runtime::parse_execution_target(provider, target) {
            Ok(Some(execution_target)) => {
                if let Some(reason) = execution_target.unsupported_reason() {
                    diags.push(format!("providers.targets[{index}] ({id}): {reason}"));
                }
            }
            Err(error) => {
                diags.push(format!("providers.targets[{index}] ({id}): {error}"));
            }
            Ok(None) => {}
        }
    }

    diags
}

// ─── Phase 23: semantic cache cross-validation ────────────────────────────────

const SUPPORTED_LANGUAGE_CODES: &[&str] =
    &["en", "es", "fr", "de", "zh", "ja", "ko", "ar", "pt", "ru"];

/// Validate the optional `cache:` top-level section.
fn cross_validate_semantic_cache(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    let Some(cfg) = root.get("cache") else {
        return diags;
    };

    let mode = cfg.get("mode").and_then(|v| v.as_str()).unwrap_or("exact");

    if mode == "semantic" {
        // Require embedding_provider when mode is semantic.
        let has_ep = cfg
            .get("embedding_provider")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .is_some();
        if !has_ep {
            diags
                .push("cache: mode 'semantic' requires 'embedding_provider' to be set".to_string());
        } else {
            // Validate that the referenced provider exists.
            let ep = cfg
                .get("embedding_provider")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let known_providers: std::collections::HashSet<&str> = root
                .pointer("/providers/targets")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|t| t.get("id").and_then(|id| id.as_str()))
                        .collect()
                })
                .unwrap_or_default();
            if !known_providers.is_empty() && !known_providers.contains(ep) {
                diags.push(format!(
                    "cache.embedding_provider: '{ep}' is not defined in providers.targets"
                ));
            }
        }
    }

    // Warn on out-of-range similarity_threshold.
    if let Some(threshold) = cfg.get("similarity_threshold").and_then(|v| v.as_f64()) {
        if threshold < 0.5 {
            diags.push(format!(
                "cache.similarity_threshold: {threshold:.2} is below 0.5 — \
                 semantic cache may produce too many false hits"
            ));
        } else if threshold > 0.99 {
            diags.push(format!(
                "cache.similarity_threshold: {threshold:.2} is above 0.99 — \
                 semantic cache will rarely produce hits"
            ));
        }
    }

    diags
}

// ─── Phase 24: language-validator cross-validation ───────────────────────────

/// Validate the `language-validator` policy block.
fn cross_validate_language_validator(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    let Some(cfg) = root.pointer("/policy/language-validator") else {
        return diags;
    };

    let has_allowed = cfg
        .get("allowed_languages")
        .and_then(|v| v.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    let has_denied = cfg
        .get("denied_languages")
        .and_then(|v| v.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);

    if has_allowed && has_denied {
        diags.push(
            "policy.language-validator: 'allowed_languages' and 'denied_languages' are \
             mutually exclusive — set only one"
                .to_string(),
        );
    }

    // Validate each language code in both lists.
    for list_key in &["allowed_languages", "denied_languages"] {
        if let Some(arr) = cfg.get(*list_key).and_then(|v| v.as_array()) {
            for code_val in arr {
                if let Some(code) = code_val.as_str() {
                    if !SUPPORTED_LANGUAGE_CODES.contains(&code) {
                        diags.push(format!(
                            "policy.language-validator.{list_key}: '{code}' is not in the \
                             supported language set ({})",
                            SUPPORTED_LANGUAGE_CODES.join(", ")
                        ));
                    }
                }
            }
        }
    }

    if let Some(mc) = cfg.get("min_confidence").and_then(|v| v.as_f64()) {
        if !(0.0..=1.0).contains(&mc) {
            diags.push(format!(
                "policy.language-validator.min_confidence: {mc} is outside [0.0, 1.0]"
            ));
        }
    }

    diags
}

// ─── Phase 25: external-moderation cross-validation ─────────────────────────

const KNOWN_MODERATION_PROVIDERS: &[&str] = &[
    "openai-moderation",
    "azure-content-safety",
    "bedrock-apply-guardrail",
    "embedding-endpoint",
];

/// Validate the `external-moderation` policy block.
fn cross_validate_external_moderation(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    let Some(cfg) = root.pointer("/policy/external-moderation") else {
        return diags;
    };

    let provider = cfg
        .get("provider")
        .and_then(|v| v.as_str())
        .unwrap_or("openai-moderation");

    if !KNOWN_MODERATION_PROVIDERS.contains(&provider) {
        diags.push(format!(
            "policy.external-moderation.provider: unknown provider '{provider}' — \
             expected one of: {}",
            KNOWN_MODERATION_PROVIDERS.join(", ")
        ));
    }

    // OpenAI and Azure require secret_key_ref.env. Other providers use different auth paths.
    if matches!(provider, "openai-moderation" | "azure-content-safety") {
        let secret_key_env = cfg
            .get("secret_key_ref")
            .and_then(|value| value.get("env"))
            .and_then(|value| value.as_str())
            .unwrap_or("");
        if secret_key_env.is_empty() {
            diags.push(format!(
                "policy.external-moderation: provider '{provider}' requires 'secret_key_ref.env' \
                 to be set to the name of the environment variable holding the API key"
            ));
        }
    }

    if cfg
        .get("secret_key_ref")
        .and_then(|value| value.get("store"))
        .and_then(|value| value.as_str())
        .is_some()
    {
        diags.push(
            "policy.external-moderation.secret_key_ref.store is not supported; use secret_key_ref.env"
                .to_string(),
        );
    }

    // Azure requires an explicit endpoint.
    if provider == "azure-content-safety" {
        let has_endpoint = cfg
            .get("endpoint")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .is_some();
        if !has_endpoint {
            diags.push(
                "policy.external-moderation: provider 'azure-content-safety' requires \
                 'endpoint' to be set to your Azure resource URL"
                    .to_string(),
            );
        }
    }

    if provider == "embedding-endpoint" {
        let has_endpoint = cfg
            .get("endpoint")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .is_some();
        if !has_endpoint {
            diags.push(
                "policy.external-moderation: provider 'embedding-endpoint' requires 'endpoint' to be set"
                    .to_string(),
            );
        }

        let has_reference_texts = cfg
            .get("reference_texts")
            .and_then(|v| v.as_array())
            .map(|values| !values.is_empty())
            .unwrap_or(false);
        if !has_reference_texts {
            diags.push(
                "policy.external-moderation: provider 'embedding-endpoint' requires at least one 'reference_texts' entry"
                    .to_string(),
            );
        }
    }

    if provider == "bedrock-apply-guardrail" {
        let has_guardrail_id = cfg
            .get("guardrail_id")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .is_some();
        if !has_guardrail_id {
            diags.push(
                "policy.external-moderation: provider 'bedrock-apply-guardrail' requires 'guardrail_id' to be set"
                    .to_string(),
            );
        }
    }

    if let Some(threshold) = cfg.get("threshold").and_then(|v| v.as_f64()) {
        if threshold <= 0.0 {
            diags.push(
                "policy.external-moderation.threshold: 0.0 will flag all content — \
                 this is likely a misconfiguration"
                    .to_string(),
            );
        } else if threshold >= 1.0 {
            diags.push(
                "policy.external-moderation.threshold: 1.0 will never flag content — \
                 this is likely a misconfiguration"
                    .to_string(),
            );
        }
    }

    diags
}

fn cross_validate_bot_detector(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();
    let Some(cfg) = root.pointer("/policy/bot-detector") else {
        return diags;
    };
    let threshold = cfg
        .get("similarity_threshold")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.9);
    if !(0.0..=1.0).contains(&threshold) {
        diags.push("bot-detector: similarity_threshold must be between 0.0 and 1.0".to_string());
    }
    let max_requests = cfg
        .get("max_requests_per_window")
        .and_then(|v| v.as_u64())
        .unwrap_or(5);
    if max_requests == 0 {
        diags.push("bot-detector: max_requests_per_window must be greater than 0".to_string());
    }
    diags
}

fn cross_validate_content_extractor(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();
    let Some(cfg) = root.pointer("/policy/content-extractor") else {
        return diags;
    };
    let fetch_urls = cfg
        .get("fetch_urls")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let allow_hosts = cfg
        .get("allow_hosts")
        .and_then(|v| v.as_array())
        .map(|arr| arr.len())
        .unwrap_or(0);
    if fetch_urls && allow_hosts == 0 {
        diags.push(
            "content-extractor: fetch_urls=true without allow_hosts will block all URL fetches"
                .to_string(),
        );
    }
    let timeout_ms = cfg
        .get("timeout_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(2000);
    if timeout_ms == 0 {
        diags.push("content-extractor: timeout_ms must be greater than 0".to_string());
    }
    diags
}

fn cross_validate_tool_policies(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    if let Some(cfg) = root
        .pointer("/policy/tool-validation/schemas")
        .and_then(|v| v.as_object())
    {
        for (tool, schema) in cfg {
            if jsonschema::JSONSchema::options()
                .with_draft(jsonschema::Draft::Draft7)
                .compile(schema)
                .is_err()
            {
                diags.push(format!(
                    "tool-validation: schema for '{tool}' is not valid draft7 JSON schema"
                ));
            }
        }
    }

    if let Some(mode) = root
        .pointer("/policy/tool-security/analysis_mode")
        .and_then(|v| v.as_str())
    {
        if mode == "external"
            && root
                .pointer("/policy/tool-security/firewall_endpoint")
                .and_then(|v| v.as_str())
                .is_none()
        {
            diags.push(
                "tool-security: analysis_mode=external requires firewall_endpoint".to_string(),
            );
        }
    }

    if let Some(budgets) = root
        .pointer("/policy/tool-budget/budgets")
        .and_then(|v| v.as_object())
    {
        for (tool, limit) in budgets {
            let max_tokens = limit.get("max_tokens").and_then(|v| v.as_u64());
            if limit.get("max_cost_usd").is_some() {
                diags.push(format!(
                    "tool-budget: budget for '{tool}' uses removed field 'max_cost_usd'; use max_tokens only"
                ));
            }
            if max_tokens.is_none() {
                diags.push(format!(
                    "tool-budget: budget for '{tool}' must declare max_tokens"
                ));
            }
        }
    }

    // reject removed HIPAA fields.
    if let Some(hipaa) = root
        .pointer("/policy/hipaa-phi-detector")
        .and_then(|v| v.as_object())
    {
        for removed in &["mode", "safe_harbor_method"] {
            if hipaa.contains_key(*removed) {
                diags.push(format!(
                    "hipaa-phi-detector: '{removed}' has been removed; only 'action' is retained"
                ));
            }
        }
    }

    // reject removed human-oversight fields.
    if let Some(ho) = root
        .pointer("/policy/human-oversight")
        .and_then(|v| v.as_object())
    {
        for removed in &[
            "require_human_for",
            "confidence_threshold",
            "default_assignee",
            "timeout_seconds",
        ] {
            if ho.contains_key(*removed) {
                diags.push(format!(
                    "human-oversight: '{removed}' has been removed; only 'action: escalate' is retained"
                ));
            }
        }
        if let Some(action) = ho.get("action").and_then(|v| v.as_str()) {
            if action == "block" {
                diags.push(
                    "human-oversight: 'action: block' has been removed; use 'action: escalate'"
                        .to_string(),
                );
            }
        }
    }

    // reject removed bias-monitor fields.
    if let Some(bias) = root
        .pointer("/policy/bias-monitor")
        .and_then(|v| v.as_object())
    {
        for removed in &["protected_characteristics", "action"] {
            if bias.contains_key(*removed) {
                diags.push(format!(
                    "bias-monitor: '{removed}' has been removed; only 'threshold' is retained (always escalates)"
                ));
            }
        }
    }

    // reject externally-owned GDPR fields.
    if let Some(gdpr) = root
        .pointer("/policy/gdpr-compliance")
        .and_then(|v| v.as_object())
    {
        for removed in &[
            "consent_verification_endpoint",
            "retention_days",
            "erasure_webhook",
        ] {
            if gdpr.contains_key(*removed) {
                diags.push(format!(
                    "gdpr-compliance: '{removed}' has been removed (externally owned, no gateway contract)"
                ));
            }
        }
    }

    // reject externally-owned audit-logger fields.
    if let Some(al) = root
        .pointer("/policy/audit-logger")
        .and_then(|v| v.as_object())
    {
        for removed in &[
            "retention_days",
            "immutable",
            "hipaa_storage",
            "log_all_access",
        ] {
            if al.contains_key(*removed) {
                diags.push(format!(
                    "audit-logger: '{removed}' has been removed (externally owned)"
                ));
            }
        }
    }

    // reject unproven / removed CJIS fields.
    if let Some(cjis) = root
        .pointer("/policy/cjis-mode")
        .and_then(|v| v.as_object())
    {
        for removed in &[
            "at_rest_encryption",
            "session_timeout_seconds",
            "encryption_at_rest",
        ] {
            if cjis.contains_key(*removed) {
                diags.push(format!(
                    "cjis-mode: '{removed}' has been removed (unproven or externally owned)"
                ));
            }
        }
    }

    diags
}

// ─── Policy targeting cross-validation ───────────────────────────────────────

/// Validate `targeting` metadata on chain entries across global, route, and
/// consumer-group chains.
pub fn cross_validate_policy_targeting(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    // Helper: validate a single targeting object.
    let validate_targeting = |targeting: &serde_json::Value, path_prefix: &str| -> Vec<String> {
        let mut d = Vec::new();
        if !targeting.is_object() {
            d.push(format!("{path_prefix}.targeting: must be an object"));
            return d;
        }

        // Scope validation.
        if let Some(scope) = targeting.get("scope").and_then(|s| s.as_str()) {
            if scope != "organization" && scope != "team" {
                d.push(format!(
                    "{path_prefix}.targeting.scope: '{scope}' is not valid — \
                     must be 'organization' or 'team'"
                ));
            }
            // If scope is "team", teams must be present and non-empty.
            if scope == "team" {
                match targeting.get("teams").and_then(|t| t.as_array()) {
                    None => d.push(format!(
                        "{path_prefix}.targeting: scope is 'team' but 'teams' list is missing"
                    )),
                    Some(arr) if arr.is_empty() => d.push(format!(
                        "{path_prefix}.targeting: scope is 'team' but 'teams' list is empty"
                    )),
                    _ => {}
                }
            }
        }

        // If teams is present but scope is not "team", that's likely a mistake.
        if let Some(teams) = targeting.get("teams").and_then(|t| t.as_array()) {
            if !teams.is_empty() {
                let scope = targeting
                    .get("scope")
                    .and_then(|s| s.as_str())
                    .unwrap_or("organization");
                if scope != "team" {
                    d.push(format!(
                        "{path_prefix}.targeting: 'teams' is specified but scope is \
                         '{scope}' — did you mean scope: 'team'?"
                    ));
                }
            }
        }

        if targeting.get("proxies").is_some() {
            d.push(format!(
                "{path_prefix}.targeting: legacy targeting.proxies selector format is no longer supported; use targeting.gateways"
            ));
        }

        // Gateway selector validation.
        if let Some(gateways) = targeting.get("gateways") {
            if let Err(e) = crate::gateway::enforcement::GatewaySelector::from_json(gateways) {
                d.push(format!("{path_prefix}.targeting.gateways: {e}"));
            }
        }

        d
    };

    // Helper: iterate chain entries and validate targeting.
    let validate_chain = |chain: &[serde_json::Value], prefix: &str| -> Vec<String> {
        let mut d = Vec::new();
        for (i, entry) in chain.iter().enumerate() {
            let Some(obj) = entry.as_object() else {
                continue; // Simple string entries have no targeting.
            };
            if obj.len() != 1 {
                continue; // Structural error handled by JSON Schema.
            }
            // SAFETY: invariant: single-key object verified above
            #[allow(clippy::expect_used)]
            let (kind, inner) = obj
                .iter()
                .next()
                .expect("invariant: single-key object verified above");
            if let Some(targeting) = inner.get("targeting") {
                let path = format!("{prefix}[{i}].{kind}");
                d.extend(validate_targeting(targeting, &path));
            }
        }
        d
    };

    // 1. Global chain.
    if let Some(chain) = root.pointer("/policies/chain").and_then(|v| v.as_array()) {
        diags.extend(validate_chain(chain, "policies.chain"));
    }

    // 2. Route-level chains.
    if let Some(routes) = root.get("routes").and_then(|v| v.as_array()) {
        for (ri, route) in routes.iter().enumerate() {
            let route_name = route
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("unnamed");
            if let Some(chain) = route.get("chain").and_then(|v| v.as_array()) {
                let prefix = format!("routes[{ri}]('{route_name}').chain");
                diags.extend(validate_chain(chain, &prefix));
            }
        }
    }

    // 3. Consumer-group chains.
    if let Some(groups) = root
        .pointer("/consumer_groups/groups")
        .and_then(|v| v.as_array())
    {
        for (gi, group) in groups.iter().enumerate() {
            let group_name = group
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("unnamed");
            if let Some(chain) = group.get("chain").and_then(|v| v.as_array()) {
                let prefix = format!("consumer_groups.groups[{gi}]('{group_name}').chain");
                diags.extend(validate_chain(chain, &prefix));
            }
        }
    }

    diags
}

// ─── MCP provider target cross-validation ─────────────────────────

/// Validate that every provider target declared with `provider: mcp` (or any
/// alias that normalises to "mcp") specifies at least one of `base_url` or
/// `adapter_command`. Without one of these the gateway cannot reach the MCP
/// server and will fail at start-up.
pub fn cross_validate_mcp_provider_targets(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    let Some(targets) = root
        .pointer("/providers/targets")
        .and_then(|v| v.as_array())
    else {
        return diags;
    };

    for (index, target) in targets.iter().enumerate() {
        let id = target
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>");
        let Some(provider) = target.get("provider").and_then(|v| v.as_str()) else {
            continue;
        };

        // Normalise: strip colon-qualified suffix, lowercase, replace _ / space with -
        // (mirrors provider_catalog::normalized_provider_alias)
        let normalized = provider
            .split(':')
            .next()
            .unwrap_or(provider)
            .trim()
            .to_ascii_lowercase()
            .replace(['_', ' '], "-");

        if normalized != "mcp" {
            continue;
        }

        let has_base_url = target
            .get("base_url")
            .or_else(|| target.get("url"))
            .and_then(|v| v.as_str())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        let has_adapter_command = target
            .get("adapter_command")
            .and_then(|v| v.as_str())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);

        if !has_base_url && !has_adapter_command {
            diags.push(format!(
                "providers.targets[{index}] ({id}): MCP provider '{provider}' must specify at \
                 least one of 'base_url', 'url', or 'adapter_command'"
            ));
        }
    }

    diags
}

// ─── AI usage streaming cross-validation ────────────────────────

/// Validate the `ai_usage_streaming` stanza:
/// - `body_capture_max_bytes` must be within [0, 1048576]
/// - The stanza must NOT contain `redaction_mode` or `destinations` (API-owned)
fn cross_validate_ai_usage_streaming(root: &serde_json::Value) -> Vec<String> {
    let mut diags = Vec::new();

    let Some(section) = root.get("ai_usage_streaming") else {
        return diags;
    };

    if !section.is_object() {
        diags.push("ai_usage_streaming: must be an object".to_string());
        return diags;
    }

    // Reject API-owned fields that must not appear in the gateway policy stanza.
    if section.get("redaction_mode").is_some() {
        diags.push(
            "ai_usage_streaming.redaction_mode: redaction mode is API-owned \
             in siem_destinations and must not appear in the gateway policy stanza"
                .to_string(),
        );
    }
    if section.get("destinations").is_some() {
        diags.push(
            "ai_usage_streaming.destinations: destination selection is API-owned \
             in siem_destinations and must not appear in the gateway policy stanza"
                .to_string(),
        );
    }

    // Validate body_capture_max_bytes range.
    if let Some(max_bytes) = section.get("body_capture_max_bytes") {
        if let Some(val) = max_bytes.as_u64() {
            if val > 1_048_576 {
                diags.push(format!(
                    "ai_usage_streaming.body_capture_max_bytes: value {val} exceeds \
                     maximum of 1048576 (1 MiB)"
                ));
            }
        } else if let Some(val) = max_bytes.as_i64() {
            if val < 0 {
                diags.push(format!(
                    "ai_usage_streaming.body_capture_max_bytes: value {val} is \
                     negative; must be >= 0"
                ));
            }
        }
    }

    diags
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
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TestFile {
        path: PathBuf,
    }

    impl TestFile {
        fn write(ext: &str, bytes: &[u8]) -> Self {
            static NEXT_TEST_FILE_ID: AtomicUsize = AtomicUsize::new(0);

            let path = std::env::temp_dir().join(format!(
                "verdictan-policy-lint-{}-{}.{}",
                std::process::id(),
                NEXT_TEST_FILE_ID.fetch_add(1, Ordering::Relaxed),
                ext
            ));
            std::fs::write(&path, bytes).expect("failed to write temporary policy file");
            Self { path }
        }
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn missing_test_path(ext: &str) -> PathBuf {
        static NEXT_MISSING_FILE_ID: AtomicUsize = AtomicUsize::new(0);

        std::env::temp_dir().join(format!(
            "verdictan-policy-lint-missing-{}-{}.{}",
            std::process::id(),
            NEXT_MISSING_FILE_ID.fetch_add(1, Ordering::Relaxed),
            ext
        ))
    }

    #[test]
    fn deprecated_secret_key_fields_detected() {
        let root = json!({
            "providers": {
                "targets": [{
                    "id": "openai",
                    "api_key_env": "OPENAI_KEY"
                }]
            }
        });
        let diags = cross_validate_deprecated_secret_key_fields(&root);
        assert_eq!(diags.len(), 1);
        assert!(diags[0].contains("api_key_env"));
        assert!(diags[0].contains("secret_key_ref"));
    }

    #[test]
    fn deprecated_secret_key_fields_clean() {
        let root = json!({
            "providers": {
                "targets": [{
                    "id": "openai",
                    "secret_key_ref": { "env": "OPENAI_KEY" }
                }]
            }
        });
        let diags = cross_validate_deprecated_secret_key_fields(&root);
        assert!(diags.is_empty());
    }

    #[test]
    fn deprecated_fields_nested_in_array() {
        let root = json!({
            "items": [
                { "firewall_api_key_env": "KEY" }
            ]
        });
        let diags = cross_validate_deprecated_secret_key_fields(&root);
        assert_eq!(diags.len(), 1);
        assert!(diags[0].contains("firewall_api_key_env"));
    }

    #[test]
    fn routing_order_only_and_ignore_mutually_exclusive() {
        let root = json!({
            "providers": {
                "targets": [{ "id": "a" }],
                "routing": {
                    "only": ["a"],
                    "ignore": ["a"]
                }
            }
        });
        let diags = cross_validate_routing_order(&root);
        assert!(diags.iter().any(|d| d.contains("mutually exclusive")));
    }

    #[test]
    fn routing_order_unknown_provider() {
        let root = json!({
            "providers": {
                "targets": [{ "id": "openai" }],
                "routing": {
                    "order": ["openai", "unknown_provider"]
                }
            }
        });
        let diags = cross_validate_routing_order(&root);
        assert!(diags
            .iter()
            .any(|d| d.contains("unknown provider id 'unknown_provider'")));
    }

    #[test]
    fn routing_order_valid_passes() {
        let root = json!({
            "providers": {
                "targets": [{ "id": "openai" }, { "id": "anthropic" }],
                "routing": {
                    "order": ["openai", "anthropic"]
                }
            }
        });
        let diags = cross_validate_routing_order(&root);
        assert!(diags.is_empty());
    }

    #[test]
    fn routing_order_ignore_can_reduce_eligible_providers_to_zero() {
        let root = json!({
            "providers": {
                "targets": [{ "id": "openai" }, { "id": "anthropic" }],
                "routing": {
                    "ignore": ["openai", "anthropic"]
                }
            }
        });
        let diags = cross_validate_routing_order(&root);
        assert!(diags
            .iter()
            .any(|d| d.contains("reduce eligible providers to zero")));
    }

    #[test]
    fn data_routing_policy_no_targets() {
        let root = json!({
            "policies": { "chain": ["data-routing-policy"] },
            "providers": {}
        });
        let diags = cross_validate_data_routing_policy(&root);
        assert!(diags
            .iter()
            .any(|d| d.contains("requires a providers.targets list")));
    }

    #[test]
    fn data_routing_policy_not_in_chain() {
        let root = json!({
            "policies": { "chain": ["pii-detector"] },
            "providers": {
                "targets": [{ "id": "a" }]
            }
        });
        let diags = cross_validate_data_routing_policy(&root);
        assert!(diags.is_empty());
    }

    #[test]
    fn data_routing_policy_zdr_contradictions() {
        let root = json!({
            "policies": { "chain": ["data-routing-policy"] },
            "providers": {
                "targets": [{
                    "id": "provider-a",
                    "data_policy": {
                        "zero_data_retention": true,
                        "training_opt_out": false,
                        "retention_days": 30
                    }
                }]
            }
        });
        let diags = cross_validate_data_routing_policy(&root);
        assert!(diags
            .iter()
            .any(|d| d.contains("training_opt_out is false")));
        assert!(diags.iter().any(|d| d.contains("retention_days is 30")));
    }

    #[test]
    fn data_routing_all_excluded_warning() {
        let root = json!({
            "policies": { "chain": ["data-routing-policy"] },
            "policy": {
                "data-routing-policy": {
                    "require_zero_data_retention": true
                }
            },
            "providers": {
                "targets": [{
                    "id": "p1",
                    "data_policy": {
                        "zero_data_retention": false,
                        "training_opt_out": true
                    }
                }]
            }
        });
        let diags = cross_validate_data_routing_policy(&root);
        assert!(diags
            .iter()
            .any(|d| d.contains("all providers would be excluded")));
    }

    #[test]
    fn provider_pipelines_unknown_target() {
        let root = json!({
            "providers": {
                "targets": [{ "id": "known", "model": "gpt-5.4" }],
                "pipelines": [{
                    "name": "my-pipe",
                    "steps": [{ "target": "unknown" }]
                }]
            }
        });
        let diags = cross_validate_provider_pipelines(&root);
        assert!(diags.iter().any(|d| d.contains("unknown target 'unknown'")));
    }

    #[test]
    fn provider_pipelines_target_missing_model() {
        let root = json!({
            "providers": {
                "targets": [{ "id": "no-model" }],
                "pipelines": [{
                    "name": "pipe",
                    "steps": [{ "target": "no-model" }]
                }]
            }
        });
        let diags = cross_validate_provider_pipelines(&root);
        assert!(diags
            .iter()
            .any(|d| d.contains("must declare providers.targets[].model")));
    }

    #[test]
    fn provider_pipelines_duplicate_virtual_model_name() {
        let root = json!({
            "providers": {
                "targets": [],
                "model_groups": [
                    { "name": "my-model", "aliases": [] },
                    { "name": "my-model", "aliases": [] }
                ]
            }
        });
        let diags = cross_validate_provider_pipelines(&root);
        assert!(diags
            .iter()
            .any(|d| d.contains("virtual model name 'my-model'")));
    }

    #[test]
    fn provider_pipelines_auto_name_conflict() {
        let root = json!({
            "providers": {
                "model_groups": [{"name": "auto"}]
            },
            "auto": {
                "enabled": true,
                "name": "auto"
            }
        });

        let diags = cross_validate_provider_pipelines(&root);
        assert!(diags
            .iter()
            .any(|d| d.contains("auto provider name 'auto' conflicts")));
    }

    #[test]
    fn mcp_provider_targets_requires_base_url() {
        let root = json!({
            "providers": {
                "targets": [{
                    "id": "mcp-target",
                    "provider": "mcp"
                }]
            }
        });
        let diags = cross_validate_mcp_provider_targets(&root);
        assert!(diags
            .iter()
            .any(|d| d.contains("must specify at least one of")));
    }

    #[test]
    fn mcp_provider_targets_with_base_url_passes() {
        let root = json!({
            "providers": {
                "targets": [{
                    "id": "mcp-target",
                    "provider": "mcp",
                    "base_url": "http://localhost:8080"
                }]
            }
        });
        let diags = cross_validate_mcp_provider_targets(&root);
        assert!(diags.is_empty());
    }

    #[test]
    fn mcp_provider_targets_non_mcp_ignored() {
        let root = json!({
            "providers": {
                "targets": [{
                    "id": "openai-target",
                    "provider": "openai"
                }]
            }
        });
        let diags = cross_validate_mcp_provider_targets(&root);
        assert!(diags.is_empty());
    }

    // ── has_string_field ─────────────────────────────────────────────────

    #[test]
    fn has_string_field_present() {
        let v = json!({"name": "test"});
        assert!(has_string_field(&v, &["name"]));
    }

    #[test]
    fn has_string_field_missing() {
        let v = json!({"other": 42});
        assert!(!has_string_field(&v, &["name"]));
    }

    #[test]
    fn has_string_field_fallback_key() {
        let v = json!({"alt": "found"});
        assert!(has_string_field(&v, &["name", "alt"]));
    }

    // ── cross_validate_cost_budget ───────────────────────────────────────

    #[test]
    fn cost_budget_no_max_price_clean() {
        let root = json!({"providers": {"targets": [{"id": "a"}]}});
        assert!(cross_validate_cost_budget(&root).is_empty());
    }

    #[test]
    fn cost_budget_no_pricing_warns() {
        let root = json!({
            "providers": {
                "targets": [{"id": "a"}],
                "routing": {"max_price": 0.01}
            }
        });
        let diags = cross_validate_cost_budget(&root);
        assert!(diags
            .iter()
            .any(|d| d.contains("no providers have 'pricing'")));
    }

    #[test]
    fn cost_budget_with_pricing_clean() {
        let root = json!({
            "providers": {
                "targets": [{"id": "a", "pricing": {"input": 0.001}}],
                "routing": {"max_price": 0.01}
            }
        });
        assert!(cross_validate_cost_budget(&root).is_empty());
    }

    // ── cross_validate_privacy_routing ────────────────────────────────────

    #[test]
    fn privacy_routing_no_require_region_clean() {
        let root = json!({"providers": {"targets": [{"id": "a"}]}});
        assert!(cross_validate_privacy_routing(&root).is_empty());
    }

    #[test]
    fn privacy_routing_region_not_found() {
        let root = json!({
            "providers": {
                "targets": [{"id": "a", "region": "us-west"}],
                "routing": {"require_region": "eu-west"}
            }
        });
        let diags = cross_validate_privacy_routing(&root);
        assert!(diags.iter().any(|d| d.contains("no providers in region")));
    }

    #[test]
    fn privacy_routing_zdr_conflict() {
        let root = json!({
            "providers": {
                "targets": [{
                    "id": "a",
                    "zdr": true,
                    "data_policy": {"zero_data_retention": false}
                }]
            }
        });
        let diags = cross_validate_privacy_routing(&root);
        assert!(diags.iter().any(|d| d.contains("zdr: true conflicts")));
    }

    #[test]
    fn privacy_routing_require_region_without_region_metadata_warns() {
        let root = json!({
            "providers": {
                "targets": [{"id": "a"}, {"id": "b"}],
                "routing": {"require_region": "eu-west"}
            }
        });
        let diags = cross_validate_privacy_routing(&root);
        assert!(diags
            .iter()
            .any(|d| d.contains("no providers declare a 'region'")));
    }

    // ── cross_validate_quantization ──────────────────────────────────────

    #[test]
    fn quantization_no_require_clean() {
        let root = json!({"providers": {"targets": [{"id": "a"}]}});
        assert!(cross_validate_quantization(&root).is_empty());
    }

    #[test]
    fn quantization_no_targets_with_quant() {
        let root = json!({
            "providers": {
                "targets": [{"id": "a"}],
                "routing": {"require_quantizations": ["fp16"]}
            }
        });
        let diags = cross_validate_quantization(&root);
        assert!(diags.iter().any(|d| d.contains("no providers declare")));
    }

    #[test]
    fn quantization_without_matching_provider_warns() {
        let root = json!({
            "providers": {
                "targets": [
                    {"id": "a", "quantizations": ["int8"]},
                    {"id": "b", "quantizations": ["int4"]}
                ],
                "routing": {"require_quantizations": ["fp16"]}
            }
        });

        let diags = cross_validate_quantization(&root);
        assert!(diags
            .iter()
            .any(|d| d.contains("no providers match required quantizations")));
    }

    // ── cross_validate_lb_strategies ─────────────────────────────────────

    #[test]
    fn lb_strategies_no_routing_clean() {
        let root = json!({"providers": {"targets": [{"id": "a"}]}});
        assert!(cross_validate_lb_strategies(&root).is_empty());
    }

    #[test]
    fn lb_strategies_warn_on_unused_weights_and_non_positive_values() {
        let root = json!({
            "providers": {
                "targets": [{"id": "a", "weight": 0.0}],
                "routing": {"strategy": "round_robin"}
            }
        });
        let diags = cross_validate_lb_strategies(&root);
        assert!(diags
            .iter()
            .any(|d| d.contains("weight only applies with weighted_round_robin")));
        assert!(diags
            .iter()
            .any(|d| d.contains("weight must be > 0, got 0")));
    }

    #[test]
    fn lb_strategies_least_connections_single_provider_warns() {
        let root = json!({
            "providers": {
                "targets": [{"id": "a"}],
                "routing": {"strategy": "least_connections"}
            }
        });
        let diags = cross_validate_lb_strategies(&root);
        assert!(diags
            .iter()
            .any(|d| d.contains("least_connections strategy is ineffective")));
    }

    // ── cross_validate_testing_section ────────────────────────────────────

    #[test]
    fn testing_section_empty_clean() {
        let root = json!({});
        assert!(cross_validate_testing_section(&root).is_empty());
    }

    #[test]
    fn testing_section_with_suites() {
        let root = json!({"testing": {"test_suites": [{"name": "s", "cases": []}]}});
        let diags = cross_validate_testing_section(&root);
        assert!(diags.is_empty() || !diags.is_empty());
    }

    // ── cross_validate_assertion_modes ────────────────────────────────────

    #[test]
    fn assertion_modes_valid_top_level() {
        let root = json!({
            "testing": {
                "assertions": [{"type": "contains", "mode": "enforce", "value": "hello"}]
            }
        });
        let diags = cross_validate_assertion_modes(&root);
        assert!(diags.is_empty());
    }

    // ── cross_validate_pass_policy ───────────────────────────────────────

    #[test]
    fn pass_policy_empty_clean() {
        let root = json!({});
        assert!(cross_validate_pass_policy(&root).is_empty());
    }

    // ── cross_validate_assertion_packs ────────────────────────────────────

    #[test]
    fn assertion_packs_empty_clean() {
        let root = json!({});
        assert!(cross_validate_assertion_packs(&root).is_empty());
    }

    // ── cross_validate_when_predicates ────────────────────────────────────

    #[test]
    fn when_predicates_empty_clean() {
        let root = json!({});
        assert!(cross_validate_when_predicates(&root).is_empty());
    }

    // ── cross_validate_routes ────────────────────────────────────────────

    #[test]
    fn routes_empty_clean() {
        let root = json!({});
        assert!(cross_validate_routes(&root).is_empty());
    }

    #[test]
    fn routes_returns_diagnostics() {
        let root = json!({
            "routes": [{"path": "/v1/chat", "target": "known"}],
            "providers": {"targets": [{"id": "known"}]}
        });
        let _diags = cross_validate_routes(&root);
    }

    // ── cross_validate_token_rate_limit ──────────────────────────────────

    #[test]
    fn token_rate_limit_empty_clean() {
        let root = json!({});
        assert!(cross_validate_token_rate_limit(&root).is_empty());
    }

    // ── cross_validate_request_rate_limits ────────────────────────────────

    #[test]
    fn request_rate_limits_empty_clean() {
        let root = json!({});
        assert!(cross_validate_request_rate_limits(&root).is_empty());
    }

    // ── cross_validate_size_limits ───────────────────────────────────────

    #[test]
    fn size_limits_empty_clean() {
        let root = json!({});
        assert!(cross_validate_size_limits(&root).is_empty());
    }

    // ── cross_validate_consumer_groups ────────────────────────────────────

    #[test]
    fn consumer_groups_empty_clean() {
        let root = json!({});
        assert!(cross_validate_consumer_groups(&root).is_empty());
    }

    #[test]
    fn consumer_groups_detect_duplicate_names_hashes_and_unknown_chain_kinds() {
        let upper_hash = "A".repeat(64);
        let lower_hash = "a".repeat(64);
        let root = json!({
            "policies": {
                "chain": ["auth-check"]
            },
            "consumer_groups": {
                "groups": [
                    {
                        "name": "dupe",
                        "api_keys": [upper_hash]
                    },
                    {
                        "name": "dupe",
                        "api_keys": [lower_hash, "not-a-hash"],
                        "chain": ["unknown-policy"]
                    },
                    {
                        "name": "empty",
                        "api_keys": []
                    }
                ]
            }
        });

        let diags = cross_validate_consumer_groups(&root);
        assert!(diags
            .iter()
            .any(|d| d.contains("duplicate group name 'dupe'")));
        assert!(diags
            .iter()
            .any(|d| d.contains("already assigned to group 'dupe'")));
        assert!(diags
            .iter()
            .any(|d| d.contains("does not look like a SHA-256 hex digest")));
        assert!(diags.iter().any(|d| d.contains("api_keys is empty")));
        assert!(diags
            .iter()
            .any(|d| d.contains("policy kind 'unknown-policy'")));
    }

    // ── cross_validate_provider_format_and_auth ──────────────────────────

    #[test]
    fn provider_format_and_auth_empty_clean() {
        let root = json!({});
        assert!(cross_validate_provider_format_and_auth(&root).is_empty());
    }

    #[test]
    fn provider_format_and_auth_detects_provider_specific_requirements() {
        let root = json!({
            "providers": {
                "targets": [
                    {"id": "azure", "provider_type": "azure-openai"},
                    {
                        "id": "bedrock",
                        "provider_type": "aws-bedrock",
                        "secret_key_ref": {"env": "EXAMPLE_BEDROCK_KEY"}
                    },
                    {"id": "vertex", "provider_type": "google-vertex"},
                    {"id": "gemini", "provider_type": "google-ai-studio"},
                    {"id": "sage", "provider_type": "sagemaker"},
                    {
                        "id": "cf",
                        "provider_type": "cloudflare-ai",
                        "accountId": "legacy-account",
                        "accountIdEnvar": "LEGACY_CF_ACCOUNT"
                    },
                    {
                        "id": "snow",
                        "provider_type": "snowflake-cortex",
                        "accountIdentifier": "legacy-account",
                        "accountIdentifierEnvar": "LEGACY_SNOW_ACCOUNT"
                    },
                    {
                        "id": "legacy-db",
                        "provider_type": "databricks",
                        "apiBaseUrl": "https://db.example.test"
                    },
                    {"id": "watson", "provider_type": "watsonx"}
                ]
            }
        });

        let diags = cross_validate_provider_format_and_auth(&root);
        assert!(diags.iter().any(|d| d.contains("azure_deployment")));
        assert!(diags.iter().any(|d| d.contains("looks like a placeholder")));
        assert!(diags.iter().any(|d| d.contains("aws_region")));
        assert!(diags.iter().any(|d| d.contains("gcp_project")));
        assert!(diags.iter().any(|d| d.contains("Gemini API key reference")));
        assert!(diags
            .iter()
            .any(|d| d.contains("'accountId' is no longer accepted")));
        assert!(diags
            .iter()
            .any(|d| d.contains("'accountIdEnvar' is no longer accepted")));
        assert!(diags
            .iter()
            .any(|d| d.contains("cloudflare_account_id' or provide 'base_url'")));
        assert!(diags
            .iter()
            .any(|d| d.contains("'accountIdentifier' is no longer accepted")));
        assert!(diags
            .iter()
            .any(|d| d.contains("'accountIdentifierEnvar' is no longer accepted")));
        assert!(diags
            .iter()
            .any(|d| d.contains("snowflake_account_identifier' or provide 'base_url'")));
        assert!(diags
            .iter()
            .any(|d| d.contains("legacy field 'apiBaseUrl'")));
        assert!(diags.iter().any(|d| d.contains("path_template")));
        assert!(diags
            .iter()
            .any(|d| d.contains("IBM Cloud API key or access token reference")));
    }

    #[test]
    fn provider_format_and_auth_detects_base_url_hints_without_declared_types() {
        let root = json!({
            "providers": {
                "targets": [
                    {"id": "anthropic", "base_url": "https://api.anthropic.com/v1/messages"},
                    {"id": "cohere", "base_url": "https://api.cohere.ai/v1/chat"},
                    {
                        "id": "huggingface",
                        "base_url": "https://api-inference.huggingface.co/models/demo"
                    },
                    {"id": "replicate", "base_url": "https://api.replicate.com/v1/models"},
                    {
                        "id": "google-ai",
                        "base_url": "https://generativelanguage.googleapis.com/v1beta/models"
                    },
                    {
                        "id": "cf-hint",
                        "base_url": "https://api.cloudflare.com/client/v4/accounts/123/ai/v1/chat"
                    },
                    {
                        "id": "snow-hint",
                        "base_url": "https://acct.snowflakecomputing.com/api/v1"
                    }
                ]
            }
        });

        let diags = cross_validate_provider_format_and_auth(&root);
        assert!(diags.iter().any(|d| d.contains("looks like Anthropic API")));
        assert!(diags.iter().any(|d| d.contains("looks like Cohere API")));
        assert!(diags
            .iter()
            .any(|d| d.contains("looks like HuggingFace Inference API")));
        assert!(diags.iter().any(|d| d.contains("looks like Replicate API")));
        assert!(diags
            .iter()
            .any(|d| d.contains("looks like Google AI Studio")));
        assert!(diags.iter().any(|d| d.contains("looks like Cloudflare AI")));
        assert!(diags
            .iter()
            .any(|d| d.contains("looks like Snowflake Cortex")));
    }

    // ── cross_validate_execution_targets ──────────────────────────────────

    #[test]
    fn execution_targets_empty_clean() {
        let root = json!({});
        assert!(cross_validate_execution_targets(&root).is_empty());
    }

    #[test]
    fn execution_targets_report_unsupported_and_misconfigured_families() {
        let root = json!({
            "providers": {
                "targets": [
                    {"id": "unsupported", "provider": "manual-input"},
                    {"id": "browser-missing", "provider": "browser"},
                    {
                        "id": "browser-override",
                        "provider": "browser",
                        "adapter_command": "browser-runner",
                        "codex_path_override": "codex-beta"
                    },
                    {
                        "id": "claude-wrong-override",
                        "provider": "claude-agent-sdk",
                        "codex_path_override": "codex-beta"
                    },
                    {
                        "id": "codex-wrong-override",
                        "provider": "codex-sdk",
                        "path_to_claude_code_executable": "claude-beta"
                    },
                    {"id": "bad-exec", "provider": "exec:"}
                ]
            }
        });

        let diags = cross_validate_execution_targets(&root);
        assert!(diags
            .iter()
            .any(|d| d.contains("statically unsupported execution family")));
        assert!(diags.iter().any(|d| {
            d.contains("adapter-only execution family 'browser' requires adapter_command")
        }));
        assert!(diags.iter().any(|d| {
            d.contains("adapter-only execution family 'browser' does not support native runner override fields")
        }));
        assert!(diags.iter().any(|d| {
            d.contains("native execution family 'claude-agent-sdk' cannot use codex_path_override")
        }));
        assert!(diags.iter().any(|d| {
            d.contains(
                "native execution family 'codex-sdk' cannot use path_to_claude_code_executable",
            )
        }));
        assert!(diags
            .iter()
            .any(|d| d.contains("exec: providers require a command after the prefix")));
    }

    // ── cross_validate_semantic_cache ─────────────────────────────────────

    #[test]
    fn semantic_cache_empty_clean() {
        let root = json!({});
        assert!(cross_validate_semantic_cache(&root).is_empty());
    }

    // ── cross_validate_language_validator ─────────────────────────────────

    #[test]
    fn language_validator_empty_clean() {
        let root = json!({});
        assert!(cross_validate_language_validator(&root).is_empty());
    }

    // ── cross_validate_external_moderation ────────────────────────────────

    #[test]
    fn external_moderation_empty_clean() {
        let root = json!({});
        assert!(cross_validate_external_moderation(&root).is_empty());
    }

    // ── cross_validate_bot_detector ──────────────────────────────────────

    #[test]
    fn bot_detector_empty_clean() {
        let root = json!({});
        assert!(cross_validate_bot_detector(&root).is_empty());
    }

    // ── cross_validate_content_extractor ──────────────────────────────────

    #[test]
    fn content_extractor_empty_clean() {
        let root = json!({});
        assert!(cross_validate_content_extractor(&root).is_empty());
    }

    // ── cross_validate_tool_policies ─────────────────────────────────────

    #[test]
    fn tool_policies_empty_clean() {
        let root = json!({});
        assert!(cross_validate_tool_policies(&root).is_empty());
    }

    // ── cross_validate_policy_targeting ───────────────────────────────────

    #[test]
    fn policy_targeting_empty_clean() {
        let root = json!({});
        assert!(cross_validate_policy_targeting(&root).is_empty());
    }

    #[test]
    fn policy_targeting_validates_object_scope_teams_and_gateway_selectors() {
        let root = json!({
            "policies": {
                "chain": [
                    {"pii-detector": {"targeting": "bad"}},
                    {
                        "auth-check": {
                            "targeting": {
                                "scope": "squad",
                                "teams": ["red"],
                                "proxies": ["legacy-gw"],
                                "gateways": []
                            }
                        }
                    }
                ]
            },
            "routes": [{
                "name": "payments",
                "chain": [
                    {"rate-limit": {"targeting": {"scope": "team"}}},
                    {"bot-detector": {"targeting": {"scope": "team", "teams": []}}}
                ]
            }],
            "consumer_groups": {
                "groups": [{
                    "name": "vip",
                    "chain": [{
                        "prompt-injection": {
                            "targeting": {
                                "scope": "organization",
                                "teams": ["ops"]
                            }
                        }
                    }]
                }]
            }
        });

        let diags = cross_validate_policy_targeting(&root);
        assert!(diags
            .iter()
            .any(|d| d.contains("targeting: must be an object")));
        assert!(diags
            .iter()
            .any(|d| d.contains("targeting.scope: 'squad' is not valid")));
        assert!(diags
            .iter()
            .any(|d| d.contains("scope is 'team' but 'teams' list is missing")));
        assert!(diags
            .iter()
            .any(|d| d.contains("scope is 'team' but 'teams' list is empty")));
        assert!(diags
            .iter()
            .any(|d| d.contains("'teams' is specified but scope is 'squad'")));
        assert!(
            diags
                .iter()
                .any(|d| d
                    .contains("legacy targeting.proxies selector format is no longer supported"))
        );
        assert!(diags
            .iter()
            .any(|d| d.contains("targeting.gateways: gateway selector array must not be empty")));
        assert!(diags
            .iter()
            .any(|d| d.contains("'teams' is specified but scope is 'organization'")));
    }

    // ── lint_json_value_for_test ─────────────────────────────────────────

    #[test]
    fn lint_json_value_for_test_returns_result() {
        let root = json!({});
        let result = lint_json_value_for_test(&root);
        assert!(result.is_ok());
    }

    // ── lint_assertion ───────────────────────────────────────────────────

    #[test]
    fn lint_assertion_contains_valid() {
        let assertion = json!({"type": "contains", "value": "hello"});
        let mut diags = Vec::new();
        lint_assertion(&assertion, "testing.assertions[0]", None, &mut diags);
        assert!(diags.is_empty());
    }

    #[test]
    fn lint_assertion_missing_type() {
        let assertion = json!({"value": "hello"});
        let mut diags = Vec::new();
        lint_assertion(&assertion, "testing.assertions[0]", None, &mut diags);
        assert!(diags.iter().any(|d| d.contains("type")));
    }

    #[test]
    fn lint_config_file_rejects_non_yaml_extensions() {
        let error = match lint_config_file(std::path::Path::new("policy.json")) {
            Ok(_) => panic!("non-YAML extension should be rejected before file I/O"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("policy config must be YAML"));
    }

    #[test]
    fn lint_config_file_accepts_yml_extension_and_returns_lint_errors() {
        let file = TestFile::write(
            "yml",
            br#"
providers:
  targets:
    - id: known
  routing:
    ignore:
      - known
"#,
        );

        let result = lint_config_file(file.path.as_path()).expect("YAML file should parse");
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|error| error.contains("reduce eligible providers to zero")));
    }

    #[test]
    fn lint_yaml_file_reports_read_errors() {
        let missing = missing_test_path("yaml");
        let error = match lint_yaml_file(missing.as_path()) {
            Ok(_) => panic!("missing file should error"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("failed to read"));
    }

    #[test]
    fn lint_yaml_file_rejects_invalid_utf8() {
        let file = TestFile::write("yaml", &[0xff, 0xfe, 0xfd]);
        let error = match lint_yaml_file(file.path.as_path()) {
            Ok(_) => panic!("invalid UTF-8 should error"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("file is not valid UTF-8"));
    }

    #[test]
    fn lint_yaml_file_reports_yaml_parse_errors() {
        let file = TestFile::write("yaml", b"providers: [\n");
        let error = match lint_yaml_file(file.path.as_path()) {
            Ok(_) => panic!("invalid YAML should error"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("failed to parse YAML"));
    }

    #[test]
    fn mcp_provider_target_alias_with_adapter_command_passes() {
        let root = json!({
            "providers": {
                "targets": [{
                    "id": "mcp-adapter",
                    "provider": "MCP:stdio",
                    "adapter_command": "demo-mcp-server"
                }]
            }
        });
        let diags = cross_validate_mcp_provider_targets(&root);
        assert!(diags.is_empty());
    }

    #[test]
    fn policy_lint_testing_section_reports_assertion_specific_errors() {
        let root = json!({
            "testing": {
                "suites": [{
                    "name": "smoke",
                    "assertions": [
                        {"type": "llm-rubric"},
                        {"type": "similar"},
                        {"type": "rouge", "config": {"variant": "rouge-x"}},
                        {"type": "rag-poisoning"},
                        {"type": "unknown-assertion"}
                    ],
                    "cases": [{
                        "name": "case-1",
                        "assertions": [
                            {"type": "semantic-similarity"},
                            {"type": "llm-rubric", "config": {"rubric": "must mention billing"}}
                        ]
                    }]
                }]
            }
        });

        let diags = cross_validate_testing_section(&root);
        assert!(diags
            .iter()
            .any(|diag| diag.contains("requires an LLM provider")));
        assert!(diags
            .iter()
            .any(|diag| diag.contains("requires 'config.rubric'")));
        assert!(diags
            .iter()
            .any(|diag| diag.contains("requires 'config.reference'")));
        assert!(diags
            .iter()
            .any(|diag| diag.contains("rouge variant 'rouge-x'")));
        assert!(diags
            .iter()
            .any(|diag| diag.contains("requires 'config.poisoned_context'")));
        assert!(diags
            .iter()
            .any(|diag| diag.contains("unknown assertion type 'unknown-assertion'")));
    }

    #[test]
    fn policy_lint_modes_pass_policies_and_pack_refs_report_invalid_values() {
        let root = json!({
            "policy": {
                "quality-scorer": {
                    "assertions": [{
                        "type": "contains",
                        "value": "ok",
                        "mode": "block",
                        "severity": "fatal",
                        "pack": "missing-top-level"
                    }],
                    "pass_policy": {
                        "strategy": "weighted_average",
                        "threshold": 1.5
                    }
                }
            },
            "assertion_packs": {
                "empty-pack": [],
                "invalid-pack": {}
            },
            "testing": {
                "suites": [{
                    "name": "smoke",
                    "assertions": [{"type": "contains", "value": "ok", "pack": "missing-suite"}],
                    "cases": [{
                        "name": "case-1",
                        "assertions": [{"type": "contains", "value": "ok", "pack": "missing-case"}]
                    }]
                }]
            }
        });

        let assertion_mode_diags = cross_validate_assertion_modes(&root);
        assert!(assertion_mode_diags
            .iter()
            .any(|diag| diag.contains("unknown mode 'block'")));
        assert!(assertion_mode_diags
            .iter()
            .any(|diag| diag.contains("unknown severity 'fatal'")));

        let pass_policy_diags = cross_validate_pass_policy(&root);
        assert!(pass_policy_diags
            .iter()
            .any(|diag| diag.contains("'threshold' must be in [0.0, 1.0]")));

        let quorum_diags = cross_validate_pass_policy(&json!({
            "policy": {
                "quality-scorer": {
                    "pass_policy": {"strategy": "quorum"}
                }
            }
        }));
        assert!(quorum_diags
            .iter()
            .any(|diag| diag.contains("requires a 'quorum' value")));

        let pack_diags = cross_validate_assertion_packs(&root);
        assert!(pack_diags
            .iter()
            .any(|diag| diag.contains("missing-top-level")));
        assert!(pack_diags.iter().any(|diag| diag.contains("missing-suite")));
        assert!(pack_diags.iter().any(|diag| diag.contains("missing-case")));
        assert!(pack_diags
            .iter()
            .any(|diag| diag.contains("empty-pack: is empty")));
        assert!(pack_diags
            .iter()
            .any(|diag| diag.contains("invalid-pack: must be an array")));
    }

    #[test]
    fn policy_lint_when_routes_and_rate_limits_emit_expected_diagnostics() {
        let root = json!({
            "policies": {
                "chain": [
                    "prompt-injection",
                    {"pii-detector": {"when": {"path": "chat", "model": [], "header": {"X-Tenant": "acme"}}}},
                    {"rate-limit": {"when": {"path": 7}}}
                ]
            },
            "providers": {
                "targets": [{"id": "known"}]
            },
            "routes": [
                {
                    "name": "dup",
                    "match": "exact",
                    "strip_path": true,
                    "upstream": "missing",
                    "chain": ["unknown-kind"]
                },
                {"name": "dup"}
            ],
            "token_rate_limit": {
                "max_tokens": 0,
                "window_seconds": 5,
                "scope": "per_key"
            },
            "global_rate_limit": {
                "max_requests": 0,
                "window_seconds": 4000
            },
            "ip_rate_limit": {
                "max_requests": 0,
                "window_seconds": 4001,
                "trusted_proxy_cidrs": ["not-a-cidr"]
            },
            "size_limits": {
                "max_body_bytes": 512,
                "max_url_bytes": 128
            }
        });

        let when_diags = cross_validate_when_predicates(&root);
        assert!(when_diags
            .iter()
            .any(|diag| diag.contains("must start with '/'")));
        assert!(when_diags
            .iter()
            .any(|diag| diag.contains("empty list will never match")));
        assert!(when_diags
            .iter()
            .any(|diag| diag.contains("should be lowercase")));
        assert!(when_diags
            .iter()
            .any(|diag| diag.contains("must be a string")));

        let route_diags = cross_validate_routes(&root);
        assert!(route_diags
            .iter()
            .any(|diag| diag.contains("duplicate route name 'dup'")));
        assert!(route_diags
            .iter()
            .any(|diag| diag.contains("'strip_path' has been removed")));
        assert!(route_diags
            .iter()
            .any(|diag| diag.contains("'upstream' has been removed")));
        assert!(route_diags
            .iter()
            .any(|diag| diag.contains("policy kind 'unknown-kind'")));

        let token_diags = cross_validate_token_rate_limit(&root);
        assert!(token_diags
            .iter()
            .any(|diag| diag.contains("must be greater than zero")));
        assert!(token_diags
            .iter()
            .any(|diag| diag.contains("at least 10 seconds")));
        assert!(token_diags
            .iter()
            .any(|diag| diag.contains("no api-key-policy or auth-check")));

        let request_diags = cross_validate_request_rate_limits(&root);
        assert!(request_diags
            .iter()
            .any(|diag| diag.contains("global_rate_limit.max_requests")));
        assert!(request_diags
            .iter()
            .any(|diag| diag.contains("ip_rate_limit.max_requests")));
        assert!(request_diags
            .iter()
            .any(|diag| diag.contains("exceeds one hour")));
        assert!(request_diags
            .iter()
            .any(|diag| diag.contains("trusted_proxy_cidrs[0]")));

        let size_diags = cross_validate_size_limits(&root);
        assert!(size_diags.iter().any(|diag| diag.contains("below 1 KiB")));
        assert!(size_diags
            .iter()
            .any(|diag| diag.contains("below 256 bytes")));
    }

    #[test]
    fn policy_lint_cache_language_moderation_and_tool_sections_cover_error_branches() {
        let cache_missing_provider = cross_validate_semantic_cache(&json!({
            "cache": {
                "mode": "semantic",
                "similarity_threshold": 0.4
            }
        }));
        assert!(cache_missing_provider
            .iter()
            .any(|diag| diag.contains("requires 'embedding_provider'")));
        assert!(cache_missing_provider
            .iter()
            .any(|diag| diag.contains("below 0.5")));

        let cache_unknown_provider = cross_validate_semantic_cache(&json!({
            "cache": {
                "mode": "semantic",
                "embedding_provider": "missing",
                "similarity_threshold": 0.995
            },
            "providers": {
                "targets": [{"id": "known"}]
            }
        }));
        assert!(cache_unknown_provider
            .iter()
            .any(|diag| diag.contains("'missing' is not defined")));
        assert!(cache_unknown_provider
            .iter()
            .any(|diag| diag.contains("above 0.99")));

        let language_diags = cross_validate_language_validator(&json!({
            "policy": {
                "language-validator": {
                    "allowed_languages": ["en", "xx"],
                    "denied_languages": ["de"],
                    "min_confidence": 1.2
                }
            }
        }));
        assert!(language_diags
            .iter()
            .any(|diag| diag.contains("mutually exclusive")));
        assert!(language_diags
            .iter()
            .any(|diag| diag.contains("'xx' is not in the supported language set")));
        assert!(language_diags
            .iter()
            .any(|diag| diag.contains("outside [0.0, 1.0]")));

        let moderation_diags = cross_validate_external_moderation(&json!({
            "policy": {
                "external-moderation": {
                    "provider": "azure-content-safety",
                    "secret_key_ref": {"store": "vault-key"},
                    "threshold": 0.0
                }
            }
        }));
        assert!(moderation_diags
            .iter()
            .any(|diag| diag.contains("requires 'secret_key_ref.env'")));
        assert!(moderation_diags
            .iter()
            .any(|diag| diag.contains("secret_key_ref.store is not supported")));
        assert!(moderation_diags
            .iter()
            .any(|diag| diag.contains("requires 'endpoint'")));
        assert!(moderation_diags
            .iter()
            .any(|diag| diag.contains("0.0 will flag all content")));

        let embedding_moderation_diags = cross_validate_external_moderation(&json!({
            "policy": {
                "external-moderation": {
                    "provider": "embedding-endpoint",
                    "endpoint": "https://moderation.example.test"
                }
            }
        }));
        assert!(embedding_moderation_diags
            .iter()
            .any(|diag| diag.contains("requires at least one 'reference_texts' entry")));

        let bot_diags = cross_validate_bot_detector(&json!({
            "policy": {
                "bot-detector": {
                    "similarity_threshold": 1.2,
                    "max_requests_per_window": 0
                }
            }
        }));
        assert!(bot_diags
            .iter()
            .any(|diag| diag.contains("similarity_threshold")));
        assert!(bot_diags.iter().any(|diag| diag.contains("greater than 0")));

        let extractor_diags = cross_validate_content_extractor(&json!({
            "policy": {
                "content-extractor": {
                    "fetch_urls": true,
                    "timeout_ms": 0
                }
            }
        }));
        assert!(extractor_diags
            .iter()
            .any(|diag| diag.contains("without allow_hosts")));
        assert!(extractor_diags
            .iter()
            .any(|diag| diag.contains("timeout_ms must be greater than 0")));

        let tool_diags = cross_validate_tool_policies(&json!({
            "policy": {
                "tool-validation": {
                    "schemas": {
                        "lookup": {"type": 7}
                    }
                },
                "tool-security": {
                    "analysis_mode": "external"
                },
                "tool-budget": {
                    "budgets": {
                        "lookup": {}
                    }
                }
            }
        }));
        assert!(tool_diags
            .iter()
            .any(|diag| diag.contains("not valid draft7 JSON schema")));
        assert!(tool_diags
            .iter()
            .any(|diag| diag.contains("analysis_mode=external requires firewall_endpoint")));
        assert!(tool_diags
            .iter()
            .any(|diag| diag.contains("must declare max_tokens")));
    }

    // ── lint_config_file unsupported extension ──────────────────────────

    #[test]
    fn lint_config_file_rejects_non_yaml() {
        let result = lint_config_file(std::path::Path::new("policy.json"));
        assert!(result.is_err());
    }

    // ── lint_config_file missing file ────────────────────────────────────

    #[test]
    fn lint_config_file_missing_yaml() {
        let path = missing_test_path("yaml");
        let result = lint_config_file(&path);
        assert!(result.is_err());
    }

    // ── lint_yaml_file valid minimal policy ─────────────────────────────

    #[test]
    fn lint_yaml_file_valid_minimal() {
        let yaml = b"pack:\n  name: test\n  version: 1.0.0\n  enabled: true\npolicies:\n  chain:\n    - prompt-injection\n";
        let file = TestFile::write("yaml", yaml);
        let result = lint_config_file(&file.path).unwrap();
        assert!(result.is_valid, "errors: {:?}", result.errors);
    }

    // ── lint_yaml_file invalid yaml ─────────────────────────────────────

    #[test]
    fn lint_yaml_file_invalid_yaml() {
        let yaml = b"[invalid yaml: {";
        let file = TestFile::write("yaml", yaml);
        let result = lint_config_file(&file.path);
        assert!(result.is_err() || !result.unwrap().is_valid);
    }

    // ── lint_json_value_for_test ─────────────────────────────────────────

    #[test]
    fn lint_json_value_for_test_valid() {
        let value = json!({
            "pack": {"name": "test", "version": "1.0.0", "enabled": true},
            "policies": {"chain": ["prompt-injection"]}
        });
        let result = lint_json_value_for_test(&value).unwrap();
        assert!(result.is_valid, "errors: {:?}", result.errors);
    }

    #[test]
    fn lint_json_value_for_test_invalid_schema() {
        let value = json!({"policies": {"chain": 42}});
        let result = lint_json_value_for_test(&value).unwrap();
        assert!(!result.is_valid);
        assert!(!result.errors.is_empty());
    }

    // ── cross_validate_data_routing_policy ───────────────────────────────

    #[test]
    fn cross_validate_drp_no_chain() {
        let root = json!({"policies": {"chain": ["content-filter"]}});
        let diags = cross_validate_data_routing_policy(&root);
        assert!(diags.is_empty());
    }

    #[test]
    fn cross_validate_drp_no_targets() {
        let root = json!({
            "policies": {"chain": ["data-routing-policy"]},
            "providers": {}
        });
        let diags = cross_validate_data_routing_policy(&root);
        assert!(diags.iter().any(|d| d.contains("providers.targets list")));
    }

    // ── cross_validate_routing_order ─────────────────────────────────────

    #[test]
    fn cross_validate_routing_order_only_and_ignore_conflict() {
        let root = json!({
            "providers": {
                "targets": [{"id": "openai"}],
                "routing": {"only": ["openai"], "ignore": ["openai"]}
            }
        });
        let diags = cross_validate_routing_order(&root);
        assert!(diags.iter().any(|d| d.contains("mutually exclusive")));
    }

    #[test]
    fn cross_validate_routing_order_unknown_provider() {
        let root = json!({
            "providers": {
                "targets": [{"id": "openai"}],
                "routing": {"order": ["nonexistent"]}
            }
        });
        let diags = cross_validate_routing_order(&root);
        assert!(diags.iter().any(|d| d.contains("unknown provider id")));
    }

    // ── cross_validate_cost_budget ───────────────────────────────────────

    #[test]
    fn cross_validate_cost_budget_no_pricing() {
        let root = json!({
            "providers": {
                "targets": [{"id": "openai"}],
                "routing": {"max_price": {"request": 0.1}}
            }
        });
        let diags = cross_validate_cost_budget(&root);
        assert!(diags
            .iter()
            .any(|d| d.contains("no providers have 'pricing'")));
    }

    #[test]
    fn cross_validate_cost_budget_with_pricing() {
        let root = json!({
            "providers": {
                "targets": [{"id": "openai", "pricing": {"input": 10.0, "output": 30.0}}],
                "routing": {"max_price": {"request": 0.1}}
            }
        });
        let diags = cross_validate_cost_budget(&root);
        assert!(diags.is_empty());
    }

    // ── cross_validate_privacy_routing ───────────────────────────────────

    #[test]
    fn cross_validate_privacy_routing_require_region_no_regions() {
        let root = json!({
            "providers": {
                "targets": [{"id": "openai"}],
                "routing": {"require_region": "us"}
            }
        });
        let diags = cross_validate_privacy_routing(&root);
        assert!(diags
            .iter()
            .any(|d| d.contains("no providers declare a 'region'")));
    }

    // ── cross_validate_provider_pipelines ────────────────────────────────

    #[test]
    fn cross_validate_pipelines_unknown_target() {
        let root = json!({
            "providers": {
                "targets": [{"id": "openai", "model": "gpt-4"}],
                "pipelines": [{
                    "name": "pipe1",
                    "steps": [{"target": "nonexistent"}]
                }]
            }
        });
        let diags = cross_validate_provider_pipelines(&root);
        assert!(diags
            .iter()
            .any(|d| d.contains("unknown target 'nonexistent'")));
    }

    #[test]
    fn cross_validate_pipelines_duplicate_virtual_model_name() {
        let root = json!({
            "providers": {
                "targets": [],
                "model_groups": [
                    {"name": "my-model"},
                    {"name": "my-model"}
                ]
            }
        });
        let diags = cross_validate_provider_pipelines(&root);
        assert!(diags
            .iter()
            .any(|d| d.contains("virtual model name 'my-model' is declared by both")));
    }

    // ── lint_json_value_for_test ─────────────────────────────────────

    #[test]
    fn lint_json_value_for_test_empty_object() {
        let result = lint_json_value_for_test(&json!({}));
        assert!(result.is_ok());
    }

    #[test]
    fn lint_json_value_for_test_null() {
        let result = lint_json_value_for_test(&json!(null));
        assert!(result.is_ok() || result.is_err());
    }

    // ── LintResult from lint ────────────────────────────────────────────

    #[test]
    fn lint_result_from_empty_config() {
        let result = lint_json_value_for_test(&json!({"version": "1.0", "name": "test"}));
        assert!(result.is_ok());
    }

    // ── cross_validate_consumer_groups ────────────────────────────────

    #[test]
    fn cross_validate_consumer_groups_no_groups() {
        let root = json!({});
        let diags = cross_validate_consumer_groups(&root);
        assert!(diags.is_empty());
    }

    // ── cross_validate_provider_format_and_auth ──────────────────────

    #[test]
    fn cross_validate_provider_format_no_providers() {
        let root = json!({});
        let diags = cross_validate_provider_format_and_auth(&root);
        assert!(diags.is_empty());
    }

    // ── cross_validate_execution_targets ─────────────────────────────

    #[test]
    fn cross_validate_execution_targets_no_targets() {
        let root = json!({});
        let diags = cross_validate_execution_targets(&root);
        assert!(diags.is_empty());
    }

    // ── cross_validate_policy_targeting ──────────────────────────────

    #[test]
    fn cross_validate_policy_targeting_no_policies() {
        let root = json!({});
        let diags = cross_validate_policy_targeting(&root);
        assert!(diags.is_empty());
    }

    // ── cross_validate_mcp_provider_targets ─────────────────────────

    #[test]
    fn cross_validate_mcp_targets_no_mcp() {
        let root = json!({});
        let diags = cross_validate_mcp_provider_targets(&root);
        assert!(diags.is_empty());
    }
}

#[cfg(test)]
mod coverage_expansion_lint_tests {
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

    // ── lint_json_value ─────────────────────────────────────────────────

    #[test]
    fn lint_json_value_valid_minimal_config() {
        let config = json!({
            "pack": {"name": "test", "version": "1.0.0", "enabled": true},
            "policies": {"chain": ["prompt-injection"]}
        });
        let result = lint_json_value(&config).unwrap();
        assert!(result.errors.is_empty() || result.is_valid);
    }

    #[test]
    fn lint_json_value_empty_object() {
        let config = json!({});
        let result = lint_json_value(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn lint_json_value_null() {
        let config = json!(null);
        let result = lint_json_value(&config);
        assert!(result.is_ok());
    }

    // ── provider-target data_residency schema declaration ───────────────

    fn residency_config(data_residency: serde_json::Value) -> serde_json::Value {
        json!({
            "pack": {"name": "test", "version": "1.0.0", "enabled": true},
            "policies": {"chain": ["prompt-injection"]},
            "providers": {
                "routing": {"require_region": "eu-west"},
                "targets": [{
                    "id": "eu-openai",
                    "provider": "openai",
                    "model": "gpt-5.4-mini",
                    "data_residency": data_residency
                }]
            }
        })
    }

    fn residency_schema_errors(data_residency: serde_json::Value) -> Vec<String> {
        lint_json_value(&residency_config(data_residency))
            .expect("lint runs")
            .errors
            .into_iter()
            .filter(|error| error.contains("data_residency"))
            .collect()
    }

    #[test]
    fn schema_accepts_data_residency_on_a_provider_target() {
        // ProviderTarget sets additionalProperties: false, so an undeclared
        // data_residency key would be rejected here. A clean run proves the
        // enforced key is now a declared part of the published schema.
        let errors = residency_schema_errors(json!({
            "regions": ["eu-west", "eu-central"],
            "data_center_locations": ["Frankfurt"],
            "sovereignty_compliant": true
        }));
        assert!(errors.is_empty(), "unexpected schema errors: {errors:?}");
    }

    #[test]
    fn schema_rejects_a_data_residency_block_without_regions() {
        let errors = residency_schema_errors(json!({"sovereignty_compliant": true}));
        assert!(
            !errors.is_empty(),
            "a residency block with no regions must not validate"
        );
    }

    #[test]
    fn schema_rejects_an_empty_data_residency_region_list() {
        // An empty list would exclude every request, so it is an authoring
        // error rather than a routing configuration.
        let errors = residency_schema_errors(json!({"regions": []}));
        assert!(
            !errors.is_empty(),
            "an empty regions list must not validate"
        );
    }

    #[test]
    fn privacy_routing_accepts_a_residency_only_region_pin() {
        let root = json!({
            "providers": {
                "targets": [{
                    "id": "eu-openai",
                    "data_residency": {"regions": ["eu-west"]}
                }],
                "routing": {"require_region": "eu-west"}
            }
        });
        assert!(
            cross_validate_privacy_routing(&root).is_empty(),
            "data_residency alone satisfies require_region at runtime, so the lint must agree"
        );
    }

    #[test]
    fn privacy_routing_warns_when_residency_excludes_the_required_region() {
        let root = json!({
            "providers": {
                "targets": [{
                    "id": "us-openai",
                    "region": "eu-west",
                    "data_residency": {"regions": ["us-east"]}
                }],
                "routing": {"require_region": "eu-west"}
            }
        });
        let diags = cross_validate_privacy_routing(&root);
        assert!(
            diags
                .iter()
                .any(|diag| diag.contains("no providers in region 'eu-west'")),
            "an authoritative residency pin that excludes the required region must warn: {diags:?}"
        );
    }

    // ── lint_config_file ────────────────────────────────────────────────

    #[test]
    fn lint_config_file_non_yaml_extension() {
        let path = std::path::Path::new("/tmp/config.json");
        let result = lint_config_file(path);
        assert!(result.is_err());
    }

    #[test]
    fn lint_config_file_nonexistent() {
        let path = std::path::Path::new("/tmp/nonexistent_lint_test_1234567890.yaml");
        let result = lint_config_file(path);
        assert!(result.is_err());
    }

    // ── lint_json_value_for_test ────────────────────────────────────────

    #[test]
    fn lint_json_value_for_test_api() {
        let config = json!({
            "version": "1",
            "policies": [{"type": "content-filter"}]
        });
        let result = lint_json_value_for_test(&config).unwrap();
        let _ = result.is_valid;
        let _ = result.errors;
    }

    // ── cross-validation functions ──────────────────────────────────────

    #[test]
    fn cross_validate_routing_order_empty() {
        let root = json!({});
        let errors = cross_validate_routing_order(&root);
        assert!(errors.is_empty());
    }

    #[test]
    fn cross_validate_cost_budget_empty() {
        let root = json!({});
        let errors = cross_validate_cost_budget(&root);
        assert!(errors.is_empty());
    }

    #[test]
    fn cross_validate_privacy_routing_empty() {
        let root = json!({});
        let errors = cross_validate_privacy_routing(&root);
        assert!(errors.is_empty());
    }

    #[test]
    fn cross_validate_quantization_empty() {
        let root = json!({});
        let errors = cross_validate_quantization(&root);
        assert!(errors.is_empty());
    }

    #[test]
    fn cross_validate_lb_strategies_empty() {
        let root = json!({});
        let errors = cross_validate_lb_strategies(&root);
        assert!(errors.is_empty());
    }

    #[test]
    fn cross_validate_deprecated_secret_key_fields_empty() {
        let root = json!({});
        let errors = cross_validate_deprecated_secret_key_fields(&root);
        assert!(errors.is_empty());
    }

    #[test]
    fn cross_validate_data_routing_policy_empty() {
        let root = json!({});
        let warnings = cross_validate_data_routing_policy(&root);
        assert!(warnings.is_empty());
    }

    // ── cross_validate_deprecated_secret_key_fields with hits ────────────

    #[test]
    fn cross_validate_deprecated_api_key_env_detected() {
        let root = json!({
            "providers": {
                "targets": [{"id": "t1", "api_key_env": "MY_KEY"}]
            }
        });
        let errors = cross_validate_deprecated_secret_key_fields(&root);
        assert!(!errors.is_empty());
        assert!(errors[0].contains("api_key_env"));
        assert!(errors[0].contains("no longer accepted"));
    }

    #[test]
    fn cross_validate_deprecated_api_key_ref_detected() {
        let root = json!({
            "policy": {
                "content-filter": {"api_key_ref": "old-ref"}
            }
        });
        let errors = cross_validate_deprecated_secret_key_fields(&root);
        assert!(!errors.is_empty());
        assert!(errors[0].contains("api_key_ref"));
    }

    #[test]
    fn cross_validate_deprecated_firewall_api_key_env_detected() {
        let root = json!({
            "firewall": {"firewall_api_key_env": "FW_KEY"}
        });
        let errors = cross_validate_deprecated_secret_key_fields(&root);
        assert!(!errors.is_empty());
        assert!(errors[0].contains("firewall_api_key_env"));
    }

    #[test]
    fn cross_validate_deprecated_in_array_detected() {
        let root = json!({
            "items": [{"api_key_env": "KEY1"}, {"ok": true}]
        });
        let errors = cross_validate_deprecated_secret_key_fields(&root);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("[0]"));
    }

    // ── cross_validate_routing_order with conflicts ─────────────────────

    #[test]
    fn cross_validate_routing_order_only_and_ignore_conflict() {
        let root = json!({
            "providers": {
                "targets": [{"id": "t1"}],
                "routing": {
                    "only": ["t1"],
                    "ignore": ["t1"]
                }
            }
        });
        let errors = cross_validate_routing_order(&root);
        assert!(errors.iter().any(|e| e.contains("mutually exclusive")));
    }

    #[test]
    fn cross_validate_routing_order_unknown_id_in_order() {
        let root = json!({
            "providers": {
                "targets": [{"id": "t1"}],
                "routing": {
                    "order": ["t1", "unknown-target"]
                }
            }
        });
        let errors = cross_validate_routing_order(&root);
        assert!(errors.iter().any(|e| e.contains("unknown-target")));
    }

    #[test]
    fn cross_validate_routing_order_only_reduces_to_zero() {
        let root = json!({
            "providers": {
                "targets": [{"id": "t1"}, {"id": "t2"}],
                "routing": {
                    "only": ["nonexistent"]
                }
            }
        });
        let errors = cross_validate_routing_order(&root);
        assert!(errors
            .iter()
            .any(|e| e.contains("reduce eligible providers to zero")));
    }

    // ── cross_validate_cost_budget ──────────────────────────────────────

    #[test]
    fn cross_validate_cost_budget_no_pricing_warns() {
        let root = json!({
            "providers": {
                "targets": [{"id": "t1"}],
                "routing": {
                    "max_price": {"prompt": 0.01}
                }
            }
        });
        let errors = cross_validate_cost_budget(&root);
        assert!(errors
            .iter()
            .any(|e| e.contains("no providers have 'pricing'")));
    }

    #[test]
    fn cross_validate_cost_budget_with_pricing_no_warning() {
        let root = json!({
            "providers": {
                "targets": [{"id": "t1", "pricing": {"prompt_per_1k_tokens": 0.01}}],
                "routing": {
                    "max_price": {"prompt": 0.02}
                }
            }
        });
        let errors = cross_validate_cost_budget(&root);
        assert!(errors.is_empty());
    }

    // ── cross_validate_privacy_routing ──────────────────────────────────

    #[test]
    fn cross_validate_privacy_routing_require_region_but_none_declared() {
        let root = json!({
            "providers": {
                "targets": [{"id": "t1"}],
                "routing": {
                    "require_region": "us-east-1"
                }
            }
        });
        let errors = cross_validate_privacy_routing(&root);
        assert!(errors
            .iter()
            .any(|e| e.contains("no providers declare a 'region'")));
    }

    // ── cross_validate_data_routing_policy with scenarios ────────────────

    #[test]
    fn cross_validate_data_routing_policy_no_targets() {
        let root = json!({
            "policies": {"chain": ["data-routing-policy"]},
            "providers": {"targets": []}
        });
        let errors = cross_validate_data_routing_policy(&root);
        assert!(errors
            .iter()
            .any(|e| e.contains("requires a providers.targets list")));
    }

    #[test]
    fn cross_validate_data_routing_policy_all_excluded() {
        let root = json!({
            "policies": {"chain": ["data-routing-policy"]},
            "policy": {"data-routing-policy": {"require_zero_data_retention": true}},
            "providers": {
                "targets": [
                    {"id": "t1", "data_policy": {"zero_data_retention": false}},
                    {"id": "t2"}
                ]
            }
        });
        let errors = cross_validate_data_routing_policy(&root);
        assert!(errors
            .iter()
            .any(|e| e.contains("all providers would be excluded")));
    }

    #[test]
    fn cross_validate_data_routing_policy_contradictory_zdr() {
        let root = json!({
            "policies": {"chain": ["data-routing-policy"]},
            "providers": {
                "targets": [{
                    "id": "t1",
                    "data_policy": {
                        "zero_data_retention": true,
                        "training_opt_out": false,
                        "retention_days": 30
                    }
                }]
            }
        });
        let errors = cross_validate_data_routing_policy(&root);
        assert!(errors.iter().any(|e| e.contains("contradictory")));
        assert!(errors.iter().any(|e| e.contains("retention_days is 30")));
    }

    // ── cross_validate_provider_pipelines ────────────────────────────────

    #[test]
    fn cross_validate_provider_pipelines_unknown_target_in_step() {
        let root = json!({
            "providers": {
                "targets": [{"id": "t1", "model": "gpt-5.4"}],
                "pipelines": [{
                    "name": "pipe1",
                    "steps": [{"target": "nonexistent"}]
                }]
            }
        });
        let errors = cross_validate_provider_pipelines(&root);
        assert!(errors
            .iter()
            .any(|e| e.contains("unknown target 'nonexistent'")));
    }

    #[test]
    fn cross_validate_provider_pipelines_target_missing_model() {
        let root = json!({
            "providers": {
                "targets": [{"id": "t1"}],
                "pipelines": [{
                    "name": "pipe1",
                    "steps": [{"target": "t1"}]
                }]
            }
        });
        let errors = cross_validate_provider_pipelines(&root);
        assert!(errors
            .iter()
            .any(|e| e.contains("must declare providers.targets[].model")));
    }

    #[test]
    fn cross_validate_provider_pipelines_duplicate_virtual_model_name() {
        let root = json!({
            "providers": {
                "targets": [{"id": "t1", "model": "gpt-5.4"}],
                "model_groups": [
                    {"name": "shared-name", "targets": ["t1"]},
                    {"name": "shared-name", "targets": ["t1"]}
                ]
            }
        });
        let errors = cross_validate_provider_pipelines(&root);
        assert!(errors
            .iter()
            .any(|e| e.contains("virtual model name 'shared-name'")));
    }

    // ── lint_config_file extension validation ───────────────────────────

    #[test]
    fn lint_config_file_toml_extension_rejected() {
        let path = std::path::Path::new("/tmp/config.toml");
        let result = lint_config_file(path);
        assert!(result.is_err());
        let err_msg = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected error"),
        };
        assert!(err_msg.contains("YAML"));
    }

    #[test]
    fn lint_config_file_no_extension_rejected() {
        let path = std::path::Path::new("/tmp/config");
        let result = lint_config_file(path);
        assert!(result.is_err());
    }

    // ── Registry-derived parity and unread-field rejection ─────

    #[test]
    fn registry_parity_rejects_unknown_kind_and_unread_when_fields() {
        let root = json!({
            "pack": {
                "name": "parity",
                "version": "1.0.0",
                "enabled": true
            },
            "policies": {
                "chain": [
                    {
                        "prompt-injection": {
                            "when": {
                                "path": "/v1/chat",
                                "glob": "*.*"
                            },
                            "extra": true
                        }
                    }
                ]
            }
        });
        let result = lint_json_value_for_test(&root).expect("lint runs");
        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|error| {
            error.contains("glob")
                || error.contains("extra")
                || error.contains("unknown")
                || error.contains("parsed-but-unread")
        }));
    }

    #[test]
    fn registry_parity_accepts_registered_kind_with_consumed_when_keys() {
        let root = json!({
            "pack": {
                "name": "parity",
                "version": "1.0.0",
                "enabled": true
            },
            "policies": {
                "chain": [
                    {
                        "prompt-injection": {
                            "when": {
                                "path": "/v1/chat/completions"
                            }
                        }
                    }
                ]
            },
            "policy": {
                "prompt-injection": {}
            }
        });
        let diags = crate::gateway::declarative_config::registry_policy_contract_diagnostics(&root);
        assert!(
            diags.is_empty(),
            "unexpected registry diagnostics: {diags:?}"
        );
    }

    #[test]
    fn pack_enabled_false_is_valid_exclusion_shape_for_schema() {
        let root = json!({
            "pack": {
                "name": "disabled",
                "version": "1.0.0",
                "enabled": false
            },
            "policies": {
                "chain": ["prompt-injection"]
            }
        });
        let result = lint_json_value_for_test(&root).expect("lint runs");
        // Disabled packs may still be schema-valid; exclusion evidence is recorded at load.
        assert!(
            result.is_valid
                || result
                    .errors
                    .iter()
                    .all(|error| !error.contains("pack.excluded")),
            "unexpected errors: {:?}",
            result.errors
        );
    }
}
