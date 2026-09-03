// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use super::auto_provider::AutoProviderConfig;
use super::providers::ProviderRegistry;

/// Configuration for the `GET /v1/models` endpoint.
#[derive(Debug, Clone, Default)]
pub struct ModelsEndpointConfig {
    pub disabled: bool,
    pub include_disabled: bool,
    pub exposed_model_ids: Vec<String>,
}

fn parse_exposed_model_ids(section: &serde_json::Value) -> Vec<String> {
    let Some(values) = section
        .get("exposed_model_ids")
        .and_then(|value| value.as_array())
    else {
        return Vec::new();
    };

    let mut seen = std::collections::HashSet::new();
    let mut ids = Vec::new();
    for value in values {
        let Some(model_id) = value
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let model_id = model_id.to_string();
        if seen.insert(model_id.clone()) {
            ids.push(model_id);
        }
    }
    ids
}

/// Parse the `models:` section from root config JSON.
pub fn parse_models_endpoint(root: &serde_json::Value) -> ModelsEndpointConfig {
    let section = match root.get("models") {
        Some(v) if v.is_object() => v,
        _ => return ModelsEndpointConfig::default(),
    };

    ModelsEndpointConfig {
        disabled: section
            .get("disabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        include_disabled: section
            .get("include_disabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        exposed_model_ids: parse_exposed_model_ids(section),
    }
}

/// A single model entry in the OpenAI `ModelList` response.
#[derive(Debug, serde::Serialize)]
struct ModelObject {
    id: String,
    object: &'static str,
    created: i64,
    owned_by: String,
}

/// Build the full `GET /v1/models` response JSON.
///
/// Collects models from provider targets, model groups, provider pipelines,
/// and the auto virtual provider. Deduplicates by `id` preserving first-seen
/// order.
pub fn build_models_response(
    registry: Option<&ProviderRegistry>,
    auto_cfg: &AutoProviderConfig,
    endpoint_cfg: &ModelsEndpointConfig,
) -> serde_json::Value {
    let mut seen = std::collections::HashSet::new();
    let mut models: Vec<ModelObject> = Vec::new();
    let exposed_model_ids = (!endpoint_cfg.exposed_model_ids.is_empty()).then(|| {
        endpoint_cfg
            .exposed_model_ids
            .iter()
            .map(String::as_str)
            .collect::<std::collections::HashSet<_>>()
    });

    let mut push = |id: String, owned_by: String| {
        if let Some(exposed_model_ids) = exposed_model_ids.as_ref() {
            if !exposed_model_ids.contains(id.as_str()) {
                return;
            }
        }
        if seen.insert(id.clone()) {
            models.push(ModelObject {
                id,
                object: "model",
                created: 0,
                owned_by,
            });
        }
    };

    if let Some(reg) = registry {
        // Concrete targets.
        for target in &reg.targets {
            if target.models.is_empty() {
                push(target.model.clone(), target.provider.clone());
            } else {
                // When a target has nested models, also expose the target's own model ID.
                push(target.model.clone(), target.provider.clone());

                for entry in &target.models {
                    if !entry.enabled && !endpoint_cfg.include_disabled {
                        continue;
                    }
                    push(entry.model_id.clone(), target.provider.clone());
                    for alias in &entry.aliases {
                        push(alias.clone(), target.provider.clone());
                    }
                }
            }
        }

        // Model groups.
        for group in &reg.model_groups {
            push(group.name.clone(), "verdictan".to_string());
            for alias in &group.aliases {
                push(alias.clone(), "verdictan".to_string());
            }
        }

        // Provider pipelines.
        for pipeline in &reg.pipelines {
            push(pipeline.name.clone(), "verdictan".to_string());
            for alias in &pipeline.aliases {
                push(alias.clone(), "verdictan".to_string());
            }
        }
    }

    // Auto virtual provider.
    if auto_cfg.enabled {
        push(auto_cfg.name.clone(), "verdictan".to_string());
    }

    serde_json::json!({
        "object": "list",
        "data": models
    })
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
    fn parse_models_endpoint_defaults_when_missing() {
        let root = json!({});
        let config = parse_models_endpoint(&root);
        assert!(!config.disabled);
        assert!(!config.include_disabled);
        assert!(config.exposed_model_ids.is_empty());
    }

    #[test]
    fn parse_models_endpoint_disabled() {
        let root = json!({"models": {"disabled": true}});
        let config = parse_models_endpoint(&root);
        assert!(config.disabled);
    }

    #[test]
    fn parse_models_endpoint_include_disabled() {
        let root = json!({"models": {"include_disabled": true}});
        let config = parse_models_endpoint(&root);
        assert!(config.include_disabled);
    }

    #[test]
    fn parse_models_endpoint_exposed_model_ids() {
        let root = json!({"models": {"exposed_model_ids": ["gpt-4", "claude-3"]}});
        let config = parse_models_endpoint(&root);
        assert_eq!(config.exposed_model_ids, vec!["gpt-4", "claude-3"]);
    }

    #[test]
    fn parse_exposed_model_ids_deduplicates() {
        let section = json!({"exposed_model_ids": ["gpt-4", "gpt-4", "claude"]});
        let ids = parse_exposed_model_ids(&section);
        assert_eq!(ids, vec!["gpt-4", "claude"]);
    }

    #[test]
    fn parse_exposed_model_ids_filters_empty() {
        let section = json!({"exposed_model_ids": ["gpt-4", "", "  ", "claude"]});
        let ids = parse_exposed_model_ids(&section);
        assert_eq!(ids, vec!["gpt-4", "claude"]);
    }

    #[test]
    fn parse_exposed_model_ids_missing() {
        let section = json!({});
        let ids = parse_exposed_model_ids(&section);
        assert!(ids.is_empty());
    }

    #[test]
    fn build_models_response_auto_only() {
        let auto_cfg = AutoProviderConfig::default();
        let endpoint_cfg = ModelsEndpointConfig::default();
        let response = build_models_response(None, &auto_cfg, &endpoint_cfg);
        assert_eq!(response["object"], "list");
        let data = response["data"].as_array().unwrap();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0]["id"], "auto");
    }

    #[test]
    fn build_models_response_auto_disabled() {
        let auto_cfg = AutoProviderConfig {
            enabled: false,
            ..Default::default()
        };
        let endpoint_cfg = ModelsEndpointConfig::default();
        let response = build_models_response(None, &auto_cfg, &endpoint_cfg);
        let data = response["data"].as_array().unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn models_endpoint_config_default() {
        let config = ModelsEndpointConfig::default();
        assert!(!config.disabled);
        assert!(!config.include_disabled);
        assert!(config.exposed_model_ids.is_empty());
    }

    #[test]
    fn parse_models_endpoint_non_object_models_ignored() {
        let root = json!({"models": "not-an-object"});
        let config = parse_models_endpoint(&root);
        assert!(!config.disabled);
    }

    #[test]
    fn parse_models_endpoint_null_models_ignored() {
        let root = json!({"models": null});
        let config = parse_models_endpoint(&root);
        assert!(!config.disabled);
    }

    #[test]
    fn parse_exposed_model_ids_non_string_values_filtered() {
        let section = json!({"exposed_model_ids": ["gpt-4", 42, null, true, "claude"]});
        let ids = parse_exposed_model_ids(&section);
        assert_eq!(ids, vec!["gpt-4", "claude"]);
    }

    #[test]
    fn build_models_response_with_registry_targets() {
        let registry = ProviderRegistry {
            targets: vec![super::super::providers::ProviderTarget {
                id: "t1".into(),
                provider: "openai".into(),
                model: "gpt-4".into(),
                models: vec![],
                ..Default::default()
            }],
            model_groups: vec![],
            pipelines: vec![],
            ..Default::default()
        };
        let auto_cfg = AutoProviderConfig {
            enabled: false,
            ..Default::default()
        };
        let endpoint_cfg = ModelsEndpointConfig::default();
        let response = build_models_response(Some(&registry), &auto_cfg, &endpoint_cfg);
        let data = response["data"].as_array().unwrap();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0]["id"], "gpt-4");
        assert_eq!(data[0]["owned_by"], "openai");
        assert_eq!(data[0]["object"], "model");
    }

    #[test]
    fn build_models_response_deduplicates() {
        let registry = ProviderRegistry {
            targets: vec![
                super::super::providers::ProviderTarget {
                    id: "t1".into(),
                    provider: "openai".into(),
                    model: "gpt-4".into(),
                    models: vec![],
                    ..Default::default()
                },
                super::super::providers::ProviderTarget {
                    id: "t2".into(),
                    provider: "openai".into(),
                    model: "gpt-4".into(),
                    models: vec![],
                    ..Default::default()
                },
            ],
            model_groups: vec![],
            pipelines: vec![],
            ..Default::default()
        };
        let auto_cfg = AutoProviderConfig {
            enabled: false,
            ..Default::default()
        };
        let endpoint_cfg = ModelsEndpointConfig::default();
        let response = build_models_response(Some(&registry), &auto_cfg, &endpoint_cfg);
        let data = response["data"].as_array().unwrap();
        assert_eq!(data.len(), 1);
    }

    #[test]
    fn build_models_response_with_exposed_filter() {
        let registry = ProviderRegistry {
            targets: vec![
                super::super::providers::ProviderTarget {
                    id: "t1".into(),
                    provider: "openai".into(),
                    model: "gpt-4".into(),
                    models: vec![],
                    ..Default::default()
                },
                super::super::providers::ProviderTarget {
                    id: "t2".into(),
                    provider: "anthropic".into(),
                    model: "claude-3".into(),
                    models: vec![],
                    ..Default::default()
                },
            ],
            model_groups: vec![],
            pipelines: vec![],
            ..Default::default()
        };
        let auto_cfg = AutoProviderConfig {
            enabled: true,
            ..Default::default()
        };
        let endpoint_cfg = ModelsEndpointConfig {
            exposed_model_ids: vec!["gpt-4".to_string()],
            ..Default::default()
        };
        let response = build_models_response(Some(&registry), &auto_cfg, &endpoint_cfg);
        let data = response["data"].as_array().unwrap();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0]["id"], "gpt-4");
    }

    #[test]
    fn build_models_response_with_model_groups() {
        let registry = ProviderRegistry {
            targets: vec![],
            model_groups: vec![super::super::providers::ModelGroup {
                name: "fast".into(),
                aliases: vec!["speed".into()],
                ..Default::default()
            }],
            pipelines: vec![],
            ..Default::default()
        };
        let auto_cfg = AutoProviderConfig {
            enabled: false,
            ..Default::default()
        };
        let endpoint_cfg = ModelsEndpointConfig::default();
        let response = build_models_response(Some(&registry), &auto_cfg, &endpoint_cfg);
        let data = response["data"].as_array().unwrap();
        assert_eq!(data.len(), 2);
        let ids: Vec<&str> = data.iter().map(|m| m["id"].as_str().unwrap()).collect();
        assert!(ids.contains(&"fast"));
        assert!(ids.contains(&"speed"));
    }

    #[test]
    fn build_models_response_with_nested_models() {
        let registry = ProviderRegistry {
            targets: vec![super::super::providers::ProviderTarget {
                id: "t1".into(),
                provider: "openai".into(),
                model: "*".into(),
                models: vec![
                    super::super::providers::ProviderModelEntry {
                        model_id: "gpt-4".into(),
                        aliases: vec!["latest".into()],
                        enabled: true,
                        ..Default::default()
                    },
                    super::super::providers::ProviderModelEntry {
                        model_id: "gpt-3.5".into(),
                        aliases: vec![],
                        enabled: false,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            model_groups: vec![],
            pipelines: vec![],
            ..Default::default()
        };
        let auto_cfg = AutoProviderConfig {
            enabled: false,
            ..Default::default()
        };
        let endpoint_cfg = ModelsEndpointConfig::default();
        let response = build_models_response(Some(&registry), &auto_cfg, &endpoint_cfg);
        let data = response["data"].as_array().unwrap();
        let ids: Vec<&str> = data.iter().map(|m| m["id"].as_str().unwrap()).collect();
        assert!(ids.contains(&"*"));
        assert!(ids.contains(&"gpt-4"));
        assert!(ids.contains(&"latest"));
        assert!(!ids.contains(&"gpt-3.5"));
    }

    #[test]
    fn build_models_response_include_disabled_models() {
        let registry = ProviderRegistry {
            targets: vec![super::super::providers::ProviderTarget {
                id: "t1".into(),
                provider: "openai".into(),
                model: "*".into(),
                models: vec![super::super::providers::ProviderModelEntry {
                    model_id: "disabled-model".into(),
                    aliases: vec![],
                    enabled: false,
                    ..Default::default()
                }],
                ..Default::default()
            }],
            model_groups: vec![],
            pipelines: vec![],
            ..Default::default()
        };
        let auto_cfg = AutoProviderConfig {
            enabled: false,
            ..Default::default()
        };
        let endpoint_cfg = ModelsEndpointConfig {
            include_disabled: true,
            ..Default::default()
        };
        let response = build_models_response(Some(&registry), &auto_cfg, &endpoint_cfg);
        let data = response["data"].as_array().unwrap();
        let ids: Vec<&str> = data.iter().map(|m| m["id"].as_str().unwrap()).collect();
        assert!(ids.contains(&"disabled-model"));
    }
}
