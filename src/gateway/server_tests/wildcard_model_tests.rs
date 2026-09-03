// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

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

fn make_target(model: &str) -> super::super::providers::ProviderTarget {
    super::super::providers::ProviderTarget {
        id: "test".into(),
        provider: "openai".into(),
        model: model.into(),
        execution_target: None,
        mcp_bridge: None,
        description: None,
        base_url: "https://api.openai.com".into(),
        api_key: String::new(),
        api_key_header: "Authorization".into(),
        api_key_prefix: "Bearer ".into(),
        secret_key_ref: None,
        path_template: None,
        headers: Default::default(),
        timeout: std::time::Duration::from_secs(30),
        stream_timeout: None,
        max_context_tokens: None,
        max_messages: None,
        data_policy: None,
        pricing: None,
        models: vec![],
        data_collection: None,
        zdr: false,
        region: None,
        quantizations: None,
        weight: None,
        provider_type: None,
        format: None,
        anthropic_version: None,
        aws_region: None,
        aws_profile: None,
        bedrock_model_family: None,
        watsonx_api_version: None,
        watsonx_project_id: None,
        watsonx_space_id: None,
        gcp_project: None,
        gcp_region: None,
        azure_api_version: None,
        azure_deployment: None,
        oauth2: None,
        health_probe: None,
        allow_insecure_tls: false,
        escalation_routing: None,
        required: false,
        data_residency: None,
        certifications: None,
    }
}

#[test]
fn wildcard_model_matches_any_requested_model() {
    let target = make_target("*");
    assert!(target_supports_model(&target, "gpt-5.4-mini"));
    assert!(target_supports_model(&target, "claude-3-sonnet"));
    assert!(target_supports_model(&target, "any-model-name"));
    // Empty model name should still not match (pre-existing behavior).
    assert!(!target_supports_model(&target, ""));
}

#[test]
fn wildcard_model_resolves_to_none() {
    let target = make_target("*");
    assert_eq!(resolve_target_model_name(&target), None);
    assert_eq!(
        resolve_catalog_model_name_for_request(&target, "gpt-5.4-mini"),
        None
    );
}

#[test]
fn explicit_model_resolves_normally() {
    let target = make_target("gpt-5.4-mini");
    assert_eq!(resolve_target_model_name(&target), Some("gpt-5.4-mini"));
    assert_eq!(
        resolve_catalog_model_name_for_request(&target, "gpt-5.4-mini"),
        Some("gpt-5.4-mini")
    );
    assert!(target_supports_model(&target, "gpt-5.4-mini"));
    assert!(!target_supports_model(&target, "claude-3-sonnet"));
}

#[test]
fn resolved_target_format_falls_back_to_provider_profile() {
    let mut target = make_target("claude-sonnet-4.5");
    target.provider = "anthropic".into();
    target.format = None;

    assert_eq!(
        resolved_target_format(&target),
        super::super::format_translation::ProviderFormat::Anthropic
    );
}

#[test]
fn nested_model_alias_resolves_to_canonical_catalog_model() {
    let mut target = make_target("*");
    target.models = vec![super::super::providers::ProviderModelEntry {
        model_id: "gpt-5.4-mini".into(),
        aliases: vec!["gpt-latest".into()],
        enabled: true,
        pricing: None,
        supported_features: vec![],
        max_output_tokens: None,
        parameter_overrides: serde_json::Map::new(),
        removed_params: vec![],
        description: None,
        escalation_routing: None,
    }];

    assert_eq!(
        resolve_catalog_model_name_for_request(&target, "gpt-latest"),
        Some("gpt-5.4-mini")
    );
}

#[test]
fn provider_prefixed_model_resolves_to_canonical_catalog_model() {
    let mut target = make_target("*");
    target.models = vec![super::super::providers::ProviderModelEntry {
        model_id: "gpt-5.4-mini".into(),
        aliases: vec![],
        enabled: true,
        pricing: None,
        supported_features: vec![],
        max_output_tokens: None,
        parameter_overrides: serde_json::Map::new(),
        removed_params: vec![],
        description: None,
        escalation_routing: None,
    }];

    assert!(target_supports_model(&target, "openai/gpt-5.4-mini"));
    assert_eq!(
        resolve_catalog_model_name_for_request(&target, "openai/gpt-5.4-mini"),
        Some("gpt-5.4-mini")
    );
}

#[test]
fn spend_log_prices_provider_prefixed_model_with_canonical_catalog_model() {
    let mut target = make_target("*");
    target.models = vec![super::super::providers::ProviderModelEntry {
        model_id: "gpt-5.4-mini".into(),
        aliases: vec![],
        enabled: true,
        pricing: Some(super::super::providers::ProviderPricing {
            input_price_per_million: 2.5,
            output_price_per_million: 10.0,
            cached_input_price_per_million: Some(1.25),
            input_multiplier: None,
            cached_input_multiplier: None,
            output_multiplier: None,
        }),
        supported_features: vec![],
        max_output_tokens: None,
        parameter_overrides: serde_json::Map::new(),
        removed_params: vec![],
        description: None,
        escalation_routing: None,
    }];
    let registry = super::super::providers::ProviderRegistry {
        targets: vec![target],
        ..Default::default()
    };
    let gateway_id: std::sync::Arc<str> = std::sync::Arc::from("gw-costs");
    let context = SpendLogContext {
        provider_registry: Some(&registry),
        catalog_snapshot: super::super::provider_catalog::CatalogSnapshot::default(),
        upstream_base: "https://api.openai.com",
        gateway_id: Some(&gateway_id),
        connected_mode: true,
        region_key: None,
        managed_public_endpoint_host: None,
        requested_region_group: None,
        current_publication: None,
        configuration_id: None,
        configuration_version_id: None,
        current_agent_id: None,
        request_finops: None,
        policy_count: 0,
        conversation_id: None,
    };
    let body = bytes::Bytes::from_static(
        br#"{"model":"openai/gpt-5.4-mini","messages":[{"role":"user","content":"Hello"}]}"#,
    );

    let payload = build_spend_log_payload_with_usage(
        context,
        "req-costs",
        &body,
        SpendUsage {
            prompt_tokens: 1_000,
            completion_tokens: 500,
            total_tokens: 1_500,
            cached_input_tokens: 0,
            ..Default::default()
        },
        false,
        Some("test"),
        None,
        None,
        256,
    )
    .expect("spend payload");

    assert_eq!(payload.provider, "openai");
    assert_eq!(payload.model, "gpt-5.4-mini");
    assert_eq!(
        payload.requested_model.as_deref(),
        Some("openai/gpt-5.4-mini")
    );
    assert_eq!(payload.model_id.as_deref(), Some("gpt-5.4-mini"));
    assert_eq!(payload.gateway_id.as_deref(), Some("gw-costs"));
    assert_eq!(payload.pricing_source, Some(PricingSource::ConfigDeclared));
    assert!((payload.prompt_cost - 0.0025).abs() < 1e-9);
    assert!((payload.completion_cost - 0.005).abs() < 1e-9);
    assert!((payload.total_cost - 0.0075).abs() < 1e-9);
    assert_eq!(
        payload
            .pricing_snapshot
            .as_ref()
            .and_then(|value| value.get("model_id"))
            .and_then(|value| value.as_str()),
        Some("gpt-5.4-mini")
    );
}

#[test]
fn spend_log_prices_provider_prefixed_model_from_catalog_snapshot() {
    let mut target = make_target("*");
    target.models = vec![super::super::providers::ProviderModelEntry {
        model_id: "gpt-5.4-mini".into(),
        aliases: vec![],
        enabled: true,
        pricing: None,
        supported_features: vec![],
        max_output_tokens: None,
        parameter_overrides: serde_json::Map::new(),
        removed_params: vec![],
        description: None,
        escalation_routing: None,
    }];
    let registry = super::super::providers::ProviderRegistry {
        targets: vec![target],
        ..Default::default()
    };
    let catalog_snapshot = super::super::provider_catalog::CatalogSnapshot {
        version: 42,
        models: vec![super::super::provider_catalog::CatalogModel {
            id: "gpt-5.4-mini".into(),
            provider_id: "openai".into(),
            model_type: "chat".into(),
            context_window: Some(128_000),
            max_output_tokens: Some(16_384),
            supported_features: vec![],
            input_token_price: Some("0.00007499999999999999".into()),
            output_token_price: Some("0.00045".into()),
            cached_input_read_price: Some("0.0000075".into()),
            parameter_overrides: serde_json::Map::new(),
            removed_params: vec![],
        }],
        ..Default::default()
    };
    let gateway_id: std::sync::Arc<str> = std::sync::Arc::from("gw-catalog-costs");
    let context = SpendLogContext {
        provider_registry: Some(&registry),
        catalog_snapshot,
        upstream_base: "https://api.openai.com",
        gateway_id: Some(&gateway_id),
        connected_mode: true,
        region_key: None,
        managed_public_endpoint_host: None,
        requested_region_group: None,
        current_publication: None,
        configuration_id: None,
        configuration_version_id: None,
        current_agent_id: None,
        request_finops: None,
        policy_count: 0,
        conversation_id: None,
    };
    let body = bytes::Bytes::from_static(
        br#"{"model":"openai/gpt-5.4-mini","messages":[{"role":"user","content":"Hello"}]}"#,
    );

    let payload = build_spend_log_payload_with_usage(
        context,
        "req-catalog-costs",
        &body,
        SpendUsage {
            prompt_tokens: 7,
            completion_tokens: 12,
            total_tokens: 19,
            cached_input_tokens: 0,
            ..Default::default()
        },
        false,
        Some("test"),
        None,
        None,
        256,
    )
    .expect("spend payload");

    assert_eq!(payload.provider, "openai");
    assert_eq!(payload.model, "gpt-5.4-mini");
    assert_eq!(payload.model_id.as_deref(), Some("gpt-5.4-mini"));
    assert_eq!(payload.pricing_source, Some(PricingSource::Catalog));
    assert!((payload.prompt_cost - 0.00000525).abs() < 1e-12);
    assert!((payload.completion_cost - 0.000054).abs() < 1e-12);
    assert!((payload.total_cost - 0.00005925).abs() < 1e-12);
    assert_eq!(payload.catalog_pricing_source.as_deref(), Some("catalog"));
    assert_eq!(
        payload
            .pricing_snapshot
            .as_ref()
            .and_then(|value| value.get("source"))
            .and_then(|value| value.as_str()),
        Some("catalog")
    );
    let input_price_per_million = payload
        .pricing_snapshot
        .as_ref()
        .and_then(|value| value.get("input_price_per_million"))
        .and_then(|value| value.as_str())
        .expect("catalog input price");
    assert_eq!(input_price_per_million, "0.7499999999999999");
    assert_eq!(
        payload.catalog_input_price.as_deref(),
        Some("0.00007499999999999999")
    );
}

#[test]
fn catalog_spend_pricing_distinguishes_missing_from_explicit_zero() {
    fn context(
        input: Option<&str>,
        output: Option<&str>,
        cached: Option<&str>,
    ) -> SpendLogContext<'static> {
        SpendLogContext {
            provider_registry: None,
            catalog_snapshot: super::super::provider_catalog::CatalogSnapshot {
                version: 42,
                models: vec![super::super::provider_catalog::CatalogModel {
                    id: "gpt-zero".into(),
                    provider_id: "openai".into(),
                    model_type: "chat".into(),
                    context_window: None,
                    max_output_tokens: None,
                    supported_features: vec![],
                    input_token_price: input.map(str::to_string),
                    output_token_price: output.map(str::to_string),
                    cached_input_read_price: cached.map(str::to_string),
                    parameter_overrides: serde_json::Map::new(),
                    removed_params: vec![],
                }],
                ..Default::default()
            },
            upstream_base: "https://api.openai.com",
            gateway_id: None,
            connected_mode: true,
            region_key: None,
            managed_public_endpoint_host: None,
            requested_region_group: None,
            current_publication: None,
            configuration_id: None,
            configuration_version_id: None,
            current_agent_id: None,
            request_finops: None,
            policy_count: 0,
            conversation_id: None,
        }
    }

    assert!(
        catalog_spend_pricing(&context(None, Some("0"), None), "openai", "gpt-zero", None)
            .is_none()
    );

    let missing_cached = catalog_spend_pricing(
        &context(Some("0"), Some("0"), None),
        "openai",
        "gpt-zero",
        None,
    )
    .expect("explicit zero prices are catalog pricing");
    let pricing = missing_cached.pricing.expect("runtime pricing");
    assert_eq!(pricing.input_price_per_million, 0.0);
    assert_eq!(pricing.output_price_per_million, 0.0);
    assert!(pricing.cached_input_price_per_million.is_none());
    assert_eq!(missing_cached.catalog_input_price.as_deref(), Some("0"));
    assert!(missing_cached
        .snapshot
        .as_ref()
        .and_then(|value| value.get("cached_input_read_price"))
        .is_some_and(serde_json::Value::is_null));

    let explicit_cached = catalog_spend_pricing(
        &context(Some("0"), Some("0"), Some("0")),
        "openai",
        "gpt-zero",
        None,
    )
    .expect("explicit cached zero");
    assert_eq!(
        explicit_cached
            .pricing
            .expect("runtime pricing")
            .cached_input_price_per_million,
        Some(0.0)
    );
    assert_eq!(
        explicit_cached
            .snapshot
            .as_ref()
            .and_then(|value| value.get("cached_input_read_price"))
            .and_then(serde_json::Value::as_str),
        Some("0")
    );
}

#[test]
fn spend_log_prefers_response_model_hint_over_unresolved_requested_model() {
    let gateway_id: std::sync::Arc<str> = std::sync::Arc::from("gw-dynamic-hint");
    let context = SpendLogContext {
        provider_registry: None,
        catalog_snapshot: super::super::provider_catalog::CatalogSnapshot::default(),
        upstream_base: crate::commands::gateway_run::DYNAMIC_PROVIDER_UPSTREAM_SENTINEL,
        gateway_id: Some(&gateway_id),
        connected_mode: true,
        region_key: None,
        managed_public_endpoint_host: None,
        requested_region_group: None,
        current_publication: None,
        configuration_id: None,
        configuration_version_id: None,
        current_agent_id: None,
        request_finops: None,
        policy_count: 0,
        conversation_id: None,
    };
    let body = bytes::Bytes::from_static(
        br#"{"model":"latest","messages":[{"role":"user","content":"Hello"}]}"#,
    );

    let payload = build_spend_log_payload_with_usage(
        context,
        "req-dynamic-hint",
        &body,
        SpendUsage {
            prompt_tokens: 10,
            completion_tokens: 5,
            total_tokens: 15,
            cached_input_tokens: 0,
            ..Default::default()
        },
        false,
        None,
        None,
        Some("openai/gpt-5.4-mini".to_string()),
        256,
    )
    .expect("spend payload");

    assert_eq!(payload.provider, "openai");
    assert_eq!(payload.model, "openai/gpt-5.4-mini");
    assert_eq!(payload.model_id.as_deref(), Some("openai/gpt-5.4-mini"));
    assert_eq!(
        payload
            .metadata
            .get("route_provider")
            .and_then(|value| value.as_str()),
        Some("openai")
    );
}

#[test]
fn spend_log_uses_requested_model_as_model_id_when_target_is_missing() {
    let gateway_id: std::sync::Arc<str> = std::sync::Arc::from("gw-dynamic-model-id");
    let context = SpendLogContext {
        provider_registry: None,
        catalog_snapshot: super::super::provider_catalog::CatalogSnapshot::default(),
        upstream_base: crate::commands::gateway_run::DYNAMIC_PROVIDER_UPSTREAM_SENTINEL,
        gateway_id: Some(&gateway_id),
        connected_mode: true,
        region_key: None,
        managed_public_endpoint_host: None,
        requested_region_group: None,
        current_publication: None,
        configuration_id: None,
        configuration_version_id: None,
        current_agent_id: None,
        request_finops: None,
        policy_count: 0,
        conversation_id: None,
    };
    let body = bytes::Bytes::from_static(
        br#"{"model":"openai/gpt-5.4-mini","messages":[{"role":"user","content":"Hello"}]}"#,
    );

    let payload = build_spend_log_payload_with_usage(
        context,
        "req-dynamic-model-id",
        &body,
        SpendUsage {
            prompt_tokens: 10,
            completion_tokens: 5,
            total_tokens: 15,
            cached_input_tokens: 0,
            ..Default::default()
        },
        false,
        None,
        None,
        None,
        256,
    )
    .expect("spend payload");

    assert_eq!(payload.provider, "openai");
    assert_eq!(payload.model, "openai/gpt-5.4-mini");
    assert_eq!(payload.model_id.as_deref(), Some("openai/gpt-5.4-mini"));
    assert_eq!(
        payload
            .metadata
            .get("route_provider")
            .and_then(|value| value.as_str()),
        Some("openai")
    );
}

#[test]
fn provider_prefixed_model_must_match_target_provider() {
    let mut target = make_target("*");
    target.provider = "anthropic".into();
    target.models = vec![super::super::providers::ProviderModelEntry {
        model_id: "claude-sonnet-4.5".into(),
        aliases: vec![],
        enabled: true,
        pricing: None,
        supported_features: vec![],
        max_output_tokens: None,
        parameter_overrides: serde_json::Map::new(),
        removed_params: vec![],
        description: None,
        escalation_routing: None,
    }];

    assert!(!target_supports_model(&target, "openai/claude-sonnet-4.5"));
    assert_eq!(
        resolve_catalog_model_name_for_request(&target, "openai/claude-sonnet-4.5"),
        None
    );
}

#[test]
fn model_parameter_metadata_copies_and_removes_request_fields() {
    let mut overrides = serde_json::Map::new();
    overrides.insert(
        "candidate_count".into(),
        serde_json::json!({"copy_from": "n"}),
    );
    overrides.insert("temperature".into(), serde_json::json!(0.25));

    let mut target = make_target("*");
    target.models = vec![super::super::providers::ProviderModelEntry {
        model_id: "gpt-5.4-mini".into(),
        aliases: vec![],
        enabled: true,
        pricing: None,
        supported_features: vec![],
        max_output_tokens: None,
        parameter_overrides: overrides,
        removed_params: vec!["n".into(), "top_p".into()],
        description: None,
        escalation_routing: None,
    }];

    let source_body = serde_json::json!({
        "model": "openai/gpt-5.4-mini",
        "n": 2,
        "top_p": 0.8
    });
    let mut provider_body = serde_json::json!({
        "n": 2,
        "top_p": 0.8
    });

    apply_target_model_request_parameter_metadata(
        &target,
        &source_body,
        &mut provider_body,
        "openai/gpt-5.4-mini",
        None,
        None,
    );

    assert_eq!(provider_body["candidate_count"], 2);
    assert_eq!(provider_body["temperature"], 0.25);
    assert!(provider_body.get("n").is_none());
    assert!(provider_body.get("top_p").is_none());
}

#[test]
fn model_parameter_metadata_falls_back_to_synced_catalog_snapshot() {
    let mut target = make_target("claude-sonnet-4.5");
    target.provider = "anthropic".into();

    let source_body = serde_json::json!({
        "model": "anthropic/claude-sonnet-4.5",
        "temperature": 0.2,
        "top_p": 0.7
    });
    let mut provider_body = serde_json::json!({
        "temperature": 0.2,
        "top_p": 0.7
    });
    let mut parameter_overrides = serde_json::Map::new();
    parameter_overrides.insert("tool_choice".into(), serde_json::json!("auto"));
    let catalog_snapshot = super::super::provider_catalog::CatalogSnapshot {
        version: 44,
        providers: Vec::new(),
        models: vec![super::super::provider_catalog::CatalogModel {
            id: "claude-sonnet-4.5".into(),
            provider_id: "anthropic".into(),
            model_type: "chat".into(),
            context_window: None,
            max_output_tokens: None,
            supported_features: Vec::new(),
            input_token_price: None,
            output_token_price: None,
            cached_input_read_price: None,
            parameter_overrides,
            removed_params: vec!["top_p".into()],
        }],
        synced_at: Some(Utc::now()),
    };

    apply_target_model_request_parameter_metadata(
        &target,
        &source_body,
        &mut provider_body,
        "anthropic/claude-sonnet-4.5",
        None,
        Some(&catalog_snapshot),
    );

    assert_eq!(provider_body["tool_choice"], "auto");
    assert_eq!(provider_body["temperature"], 0.2);
    assert!(provider_body.get("top_p").is_none());
}

#[test]
fn model_capability_validation_falls_back_to_synced_catalog_features() {
    let mut target = make_target("claude-sonnet-4.5");
    target.provider = "anthropic".into();

    let request_body = serde_json::json!({
        "model": "anthropic/claude-sonnet-4.5",
        "messages": [{"role": "user", "content": "hello"}],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "weather",
                "schema": {"type": "object"}
            }
        }
    });
    let request_contract = super::super::runtime_capabilities::RuntimeCapabilityRequest {
        family: super::super::runtime_capabilities::RequestFamily::ChatCompletions,
        input_modalities: vec![super::super::runtime_capabilities::InputModality::Text],
        output_modalities: vec![super::super::runtime_capabilities::OutputModality::Text],
        interaction_features: Vec::new(),
        transport_mode: super::super::runtime_capabilities::TransportMode::Json,
        response_format_feature: Some(
            super::super::runtime_capabilities::ResponseFormatFeature::JsonSchema,
        ),
        routing_policy_features: Vec::new(),
        caching_features: Vec::new(),
        plugin_features: Vec::new(),
        beta_headers: Vec::new(),
        requires_strict_mode: false,
    };
    let catalog_snapshot = super::super::provider_catalog::CatalogSnapshot {
        version: 44,
        providers: Vec::new(),
        models: vec![super::super::provider_catalog::CatalogModel {
            id: "claude-sonnet-4.5".into(),
            provider_id: "anthropic".into(),
            model_type: "chat".into(),
            context_window: None,
            max_output_tokens: None,
            supported_features: vec!["tools".into()],
            input_token_price: None,
            output_token_price: None,
            cached_input_read_price: None,
            parameter_overrides: serde_json::Map::new(),
            removed_params: Vec::new(),
        }],
        synced_at: Some(Utc::now()),
    };

    let error = validate_target_model_capabilities(
        &target,
        &request_body,
        &request_contract,
        "anthropic/claude-sonnet-4.5",
        None,
        Some(&catalog_snapshot),
    )
    .expect_err("catalog-backed response format validation should reject request");
    assert!(matches!(
        error,
        super::super::runtime_capabilities::RuntimeCapabilityError::UnsupportedModelResponseFormat {
            model,
            feature
        } if model == "claude-sonnet-4.5" && feature == "json_schema"
    ));
}

#[test]
fn model_capability_validation_falls_back_to_synced_catalog_max_output_tokens() {
    let mut target = make_target("claude-sonnet-4.5");
    target.provider = "anthropic".into();

    let request_body = serde_json::json!({
        "model": "anthropic/claude-sonnet-4.5",
        "messages": [{"role": "user", "content": "hello"}],
        "max_output_tokens": 128
    });
    let request_contract = super::super::runtime_capabilities::RuntimeCapabilityRequest {
        family: super::super::runtime_capabilities::RequestFamily::ChatCompletions,
        input_modalities: vec![super::super::runtime_capabilities::InputModality::Text],
        output_modalities: vec![super::super::runtime_capabilities::OutputModality::Text],
        interaction_features: Vec::new(),
        transport_mode: super::super::runtime_capabilities::TransportMode::Json,
        response_format_feature: None,
        routing_policy_features: Vec::new(),
        caching_features: Vec::new(),
        plugin_features: Vec::new(),
        beta_headers: Vec::new(),
        requires_strict_mode: false,
    };
    let catalog_snapshot = super::super::provider_catalog::CatalogSnapshot {
        version: 44,
        providers: Vec::new(),
        models: vec![super::super::provider_catalog::CatalogModel {
            id: "claude-sonnet-4.5".into(),
            provider_id: "anthropic".into(),
            model_type: "chat".into(),
            context_window: None,
            max_output_tokens: Some(64),
            supported_features: Vec::new(),
            input_token_price: None,
            output_token_price: None,
            cached_input_read_price: None,
            parameter_overrides: serde_json::Map::new(),
            removed_params: Vec::new(),
        }],
        synced_at: Some(Utc::now()),
    };

    let error = validate_target_model_capabilities(
        &target,
        &request_body,
        &request_contract,
        "anthropic/claude-sonnet-4.5",
        None,
        Some(&catalog_snapshot),
    )
    .expect_err("catalog-backed max token validation should reject request");
    assert!(matches!(
        error,
        super::super::runtime_capabilities::RuntimeCapabilityError::MaxOutputTokensExceeded {
            model,
            requested,
            max_output_tokens
        } if model == "claude-sonnet-4.5"
            && requested == 128
            && max_output_tokens == 64
    ));
}
