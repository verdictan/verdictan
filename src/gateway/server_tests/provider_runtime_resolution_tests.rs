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

use std::ffi::OsString;

use super::*;
use crate::gateway::provider_auth::ProviderType;
use crate::secret_key_ref::SecretKeyReference;

struct ScopedEnvVar {
    key: &'static str,
    original: Option<OsString>,
}

impl ScopedEnvVar {
    fn set(key: &'static str, value: &str) -> Self {
        let original = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, original }
    }

    fn clear(key: &'static str) -> Self {
        let original = std::env::var_os(key);
        std::env::remove_var(key);
        Self { key, original }
    }
}

impl Drop for ScopedEnvVar {
    fn drop(&mut self) {
        match &self.original {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
    }
}

fn make_target(
    secret_key_ref: Option<SecretKeyReference>,
) -> super::super::providers::ProviderTarget {
    super::super::providers::ProviderTarget {
        id: "openai-primary".into(),
        provider: "openai".into(),
        model: "gpt-5.4-mini".into(),
        execution_target: None,
        mcp_bridge: None,
        description: None,
        base_url: "https://api.openai.com".into(),
        api_key: String::new(),
        api_key_header: "Authorization".into(),
        api_key_prefix: "Bearer ".into(),
        secret_key_ref,
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
        provider_type: Some(ProviderType::OpenAI),
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
fn optional_local_api_key_fallback_reads_store_env_for_optional_target() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    let _prefixed = ScopedEnvVar::clear("VERDICTAN_OPENAI_API_KEY");
    let _env = ScopedEnvVar::set("OPENAI_API_KEY", "test-openai-key");
    let target = make_target(Some(SecretKeyReference {
        env: None,
        store: Some("OPENAI_API_KEY".into()),
        scope: None,
        keychain: None,
    }));

    let resolved = optional_local_api_key_fallback(&target, true).expect("fallback key");

    assert_eq!(resolved.0, "OPENAI_API_KEY");
    assert_eq!(resolved.1, "test-openai-key");
}

#[test]
fn optional_local_api_key_fallback_prefers_verdictan_prefixed_store_env() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    let _generic = ScopedEnvVar::set("OPENAI_API_KEY", "generic-openai-key");
    let _prefixed = ScopedEnvVar::set("VERDICTAN_OPENAI_API_KEY", "prefixed-openai-key");
    let target = make_target(Some(SecretKeyReference {
        env: None,
        store: Some("OPENAI_API_KEY".into()),
        scope: None,
        keychain: None,
    }));

    let resolved = optional_local_api_key_fallback(&target, true).expect("fallback key");

    assert_eq!(resolved.0, "VERDICTAN_OPENAI_API_KEY");
    assert_eq!(resolved.1, "prefixed-openai-key");
}

#[test]
fn optional_local_api_key_fallback_respects_source_and_trims_blank_values() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    let _prefixed = ScopedEnvVar::clear("VERDICTAN_OPENAI_API_KEY");
    let store_ref = make_target(Some(SecretKeyReference {
        env: None,
        store: Some("OPENAI_API_KEY".into()),
        scope: None,
        keychain: None,
    }));
    let env_ref = make_target(Some(SecretKeyReference::from_env("OPENAI_API_KEY")));

    let _blank = ScopedEnvVar::set("OPENAI_API_KEY", "   ");
    assert!(optional_local_api_key_fallback(&store_ref, true).is_none());
    assert!(optional_local_api_key_fallback(&env_ref, false).is_none());
    drop(_blank);

    let _value = ScopedEnvVar::set("OPENAI_API_KEY", "fallback-key");
    assert!(optional_local_api_key_fallback(&store_ref, false).is_none());
    let resolved = optional_local_api_key_fallback(&env_ref, false).expect("env fallback");
    assert_eq!(resolved.0, "OPENAI_API_KEY");
    assert_eq!(resolved.1, "fallback-key");
}

#[test]
fn optional_local_api_key_fallback_uses_verdictan_prefixed_store_env_when_generic_missing() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    let _generic = ScopedEnvVar::clear("OPENAI_API_KEY");
    let _prefixed = ScopedEnvVar::set("VERDICTAN_OPENAI_API_KEY", "prefixed-fallback");
    let target = make_target(Some(SecretKeyReference {
        env: None,
        store: Some("OPENAI_API_KEY".into()),
        scope: None,
        keychain: None,
    }));

    let resolved = optional_local_api_key_fallback(&target, true).expect("prefixed fallback");

    assert_eq!(resolved.0, "VERDICTAN_OPENAI_API_KEY");
    assert_eq!(resolved.1, "prefixed-fallback");
}

#[test]
fn optional_local_api_key_fallback_skips_required_and_preconfigured_targets() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    let _prefixed = ScopedEnvVar::clear("VERDICTAN_OPENAI_API_KEY");
    let _env = ScopedEnvVar::set("OPENAI_API_KEY", "test-openai-key");

    let mut required_target = make_target(Some(SecretKeyReference::from_env("OPENAI_API_KEY")));
    required_target.required = true;
    assert!(optional_local_api_key_fallback(&required_target, true).is_none());

    let mut preconfigured_target =
        make_target(Some(SecretKeyReference::from_env("OPENAI_API_KEY")));
    preconfigured_target.api_key = "already-configured".into();
    assert!(optional_local_api_key_fallback(&preconfigured_target, true).is_none());
}

#[test]
fn resolve_local_provider_target_marks_missing_optional_env_target_inactive() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    let _env = ScopedEnvVar::clear("OPENAI_API_KEY");
    let target = make_target(Some(SecretKeyReference::from_env("OPENAI_API_KEY")));

    match resolve_local_provider_target(&target, false, false) {
        ConnectedTargetResolution::Ready(_) => {
            panic!("missing optional env target should not stay active")
        }
        ConnectedTargetResolution::Inactive {
            status,
            message,
            status_reason,
        } => {
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(status_reason, "provider_key_not_configured");
            assert!(message.contains("OPENAI_API_KEY"));
        }
    }
}

#[test]
fn resolve_local_provider_target_uses_env_fallback_when_available() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    let _env = ScopedEnvVar::set("OPENAI_API_KEY", "local-fallback");
    let target = make_target(Some(SecretKeyReference::from_env("OPENAI_API_KEY")));

    match resolve_local_provider_target(&target, false, false) {
        ConnectedTargetResolution::Ready(prepared) => {
            assert_eq!(prepared.api_key, "local-fallback");
        }
        ConnectedTargetResolution::Inactive { .. } => {
            panic!("env-backed fallback should keep target ready")
        }
    }
}

#[test]
fn resolve_local_provider_target_leaves_optional_self_managed_targets_ready() {
    // google-vertex is the remaining available self-managed provider (bedrock was
    // removed from runtime dispatch); it uses its own credential chain and needs
    // no api key, so it must resolve ready without auth material.
    let mut target = make_target(None);
    target.provider = "google-vertex".into();
    target.provider_type = Some(ProviderType::GoogleVertex);

    match resolve_local_provider_target(&target, false, false) {
        ConnectedTargetResolution::Ready(prepared) => {
            assert!(prepared.api_key.is_empty());
        }
        ConnectedTargetResolution::Inactive { .. } => {
            panic!("self-managed target without auth material should stay ready")
        }
    }
}

#[test]
fn connected_provider_key_local_fallback_is_limited_to_missing_key_states() {
    assert!(connected_provider_key_status_allows_local_fallback(
        "provider_key_not_configured"
    ));
    assert!(connected_provider_key_status_allows_local_fallback(
        "provider_key_seeded_default_deleted"
    ));
    assert!(!connected_provider_key_status_allows_local_fallback(
        "provider_key_policy_denied"
    ));
    assert!(!connected_provider_key_status_allows_local_fallback(
        "provider_key_no_policy_binding"
    ));
    assert!(!connected_provider_key_status_allows_local_fallback(
        "organization_not_active"
    ));
}

#[test]
fn provider_target_startup_status_covers_local_self_managed_and_missing_key_paths() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    let _env = ScopedEnvVar::clear("OPENAI_API_KEY");

    let mut execution_target = make_target(None);
    execution_target.execution_target =
        Some(crate::gateway::execution_runtime::ExecutionTarget::Echo);
    assert_eq!(
        provider_target_startup_status(false, &execution_target),
        (
            "ready",
            "local or self-hosted execution target is available".to_string(),
        )
    );
    assert_eq!(
        provider_target_startup_status(true, &execution_target),
        (
            "inactive",
            "connected gateways do not execute local or self-hosted targets".to_string(),
        )
    );

    let mut self_managed = make_target(None);
    self_managed.provider = "google-vertex".into();
    self_managed.provider_type = Some(ProviderType::GoogleVertex);
    assert_eq!(
        provider_target_startup_status(false, &self_managed),
        (
            "ready",
            "provider uses optional or self-managed credentials".to_string(),
        )
    );

    let mut resolved_key = make_target(None);
    resolved_key.api_key = "resolved-key".into();
    assert_eq!(
        provider_target_startup_status(false, &resolved_key),
        (
            "ready",
            "environment-backed credential resolved".to_string(),
        )
    );

    let missing_key = make_target(Some(SecretKeyReference::from_env("OPENAI_API_KEY")));
    let (status, reason) = provider_target_startup_status(false, &missing_key);
    assert_eq!(status, "inactive");
    assert!(reason.contains("OPENAI_API_KEY"));
}

#[test]
fn provider_target_startup_status_connected_control_plane_key_is_pending() {
    let _guard = crate::test_support::env_lock().lock().unwrap();
    let target = make_target(Some(SecretKeyReference {
        env: None,
        store: Some("OPENAI_API_KEY".into()),
        scope: None,
        keychain: None,
    }));

    let _prefixed_cleared = ScopedEnvVar::clear("VERDICTAN_OPENAI_API_KEY");
    let _cleared = ScopedEnvVar::clear("OPENAI_API_KEY");
    let (status, reason) = provider_target_startup_status(true, &target);
    assert_eq!(status, "pending");
    assert!(reason.contains("waiting for connected provider-key resolution"));
    assert!(!reason.contains("local env fallback available"));
    drop(_cleared);

    let _prefixed_present = ScopedEnvVar::clear("VERDICTAN_OPENAI_API_KEY");
    let _present = ScopedEnvVar::set("OPENAI_API_KEY", "local-fallback");
    let (status, reason) = provider_target_startup_status(true, &target);
    assert_eq!(status, "pending");
    assert!(reason.contains("local env fallback available"));
}

#[test]
fn missing_local_provider_key_message_distinguishes_store_backed_modes() {
    let target = make_target(Some(SecretKeyReference {
        env: None,
        store: Some("OPENAI_API_KEY".into()),
        scope: None,
        keychain: None,
    }));

    let local = missing_local_provider_key_message(&target, false);
    assert!(local.contains("store-backed secret 'OPENAI_API_KEY'"));
    assert!(local.contains("matching local env fallback"));

    let connected = missing_local_provider_key_message(&target, true);
    assert!(connected.contains("provider key 'OPENAI_API_KEY'"));
    assert!(connected.contains("control plane"));
}

#[test]
fn missing_local_provider_key_message_without_reference_is_generic() {
    let message = missing_local_provider_key_message(&make_target(None), false);
    assert!(message.contains("provider key is not configured"));
}

#[test]
fn connected_missing_provider_registry_message_mentions_deployment() {
    assert!(missing_provider_registry_message(true).contains("deploy"));
    assert!(missing_provider_registry_message(false).contains("providers section"));
}
