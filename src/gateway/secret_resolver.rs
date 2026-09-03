// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

#![allow(clippy::items_after_test_module)]

use crate::gateway::{declarative_config::LoadedDeclarativeConfig, server::EventSink};
use std::collections::HashSet;

const GLOBAL_DEFAULT_PROVIDER_BUNDLE_ALIAS: &str = "global-default";

/// Header names that can carry an upstream provider credential.
///
/// A provider bundle transports routing configuration only. The gateway
/// rejects a bundle that supplies one of these headers, because the header
/// value would become a platform-supplied credential.
const CREDENTIAL_BEARING_HEADERS: [&str; 7] = [
    "authorization",
    "proxy-authorization",
    "api-key",
    "x-api-key",
    "x-goog-api-key",
    "x-api-token",
    "anthropic-api-key",
];

use crate::gateway::removed_provider_access_contract::REMOVED_MANAGED_ACCESS_FIELDS;

fn is_platform_scope(scope: Option<&str>) -> bool {
    matches!(
        scope.map(str::trim).filter(|value| !value.is_empty()),
        Some("platform")
    )
}

fn all_provider_target_ids(loaded: &LoadedDeclarativeConfig) -> HashSet<String> {
    loaded
        .provider_registry
        .as_ref()
        .map(|registry| {
            registry
                .targets
                .iter()
                .map(|target| target.id.clone())
                .collect()
        })
        .unwrap_or_default()
}

fn validate_overlay_platform_secret_policy(
    overlay_label: &str,
    protected_target_ids: &HashSet<String>,
    overlay: &LoadedDeclarativeConfig,
) -> Result<(), anyhow::Error> {
    let Some(registry) = overlay.provider_registry.as_ref() else {
        return Ok(());
    };

    for target in &registry.targets {
        if target
            .secret_key_ref
            .as_ref()
            .map(|reference| is_platform_scope(reference.scope_name()))
            .unwrap_or(false)
        {
            anyhow::bail!(
                "{overlay_label} may not declare platform-scoped provider secrets on target {}",
                target.id
            );
        }
        if protected_target_ids.contains(target.id.as_str()) {
            anyhow::bail!(
                "{overlay_label} may not override platform-managed target {}",
                target.id
            );
        }
    }

    Ok(())
}

/// Reject a provider bundle that carries provider credentials or removed
/// managed-access controls.
///
/// The control plane applies the same rules when it stores a bundle. The
/// gateway applies them again, because an older control plane can still send
/// a bundle that contains a literal key, a credential-bearing header, a
/// platform secret scope, or a managed fallback control.
fn validate_provider_bundle_registry(
    bundle_key: &str,
    registry: &serde_json::Value,
) -> Result<(), anyhow::Error> {
    fn reject(bundle_key: &str, path: &str, reason: &str) -> anyhow::Error {
        anyhow::anyhow!("platform provider bundle {bundle_key} at {path} {reason}")
    }

    fn visit(bundle_key: &str, path: &str, value: &serde_json::Value) -> Result<(), anyhow::Error> {
        match value {
            serde_json::Value::Object(entries) => {
                for field in REMOVED_MANAGED_ACCESS_FIELDS {
                    if entries.contains_key(field) {
                        return Err(reject(
                            bundle_key,
                            path,
                            &format!("declares removed managed-access field '{field}'"),
                        ));
                    }
                }

                if entries
                    .get("api_key")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|key| !key.trim().is_empty())
                {
                    return Err(reject(bundle_key, path, "declares a literal api_key value"));
                }

                if entries
                    .get("secret_key_ref")
                    .and_then(|reference| reference.get("scope"))
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    == Some("platform")
                {
                    return Err(reject(
                        bundle_key,
                        path,
                        "declares a platform-scoped secret_key_ref",
                    ));
                }

                if let Some(headers) = entries.get("headers").and_then(|value| value.as_object()) {
                    for (name, header_value) in headers {
                        let normalized = name.trim().to_ascii_lowercase();
                        if !CREDENTIAL_BEARING_HEADERS.contains(&normalized.as_str()) {
                            continue;
                        }
                        let carries_value = match header_value {
                            serde_json::Value::String(text) => !text.trim().is_empty(),
                            serde_json::Value::Null => false,
                            _ => true,
                        };
                        if carries_value {
                            return Err(reject(
                                bundle_key,
                                path,
                                &format!("declares credential-bearing header '{normalized}'"),
                            ));
                        }
                    }
                }

                for (key, child) in entries {
                    visit(bundle_key, &format!("{path}.{key}"), child)?;
                }
            }
            serde_json::Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    visit(bundle_key, &format!("{path}[{index}]"), item)?;
                }
            }
            _ => {}
        }

        Ok(())
    }

    visit(bundle_key, "providers", registry)
}

fn build_platform_provider_bundle_overlay(
    provider_bundle: &RuntimePlatformProviderBundleResponse,
) -> Result<LoadedDeclarativeConfig, anyhow::Error> {
    validate_provider_bundle_registry(
        &provider_bundle.bundle_key,
        &provider_bundle.provider_registry,
    )?;

    let raw = serde_json::to_vec(&serde_json::json!({
        "providers": provider_bundle.provider_registry.clone()
    }))?;
    LoadedDeclarativeConfig::from_bytes(&raw).map_err(|error| {
        anyhow::anyhow!(
            "platform provider bundle {} parse failed: {error}",
            provider_bundle.bundle_key
        )
    })
}

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct RuntimePlatformProviderBundleResponse {
    pub bundle_key: String,
    pub provider_registry: serde_json::Value,
    pub _version: i32,
}

impl EventSink {
    async fn fetch_org_platform_provider_bundle(
        &self,
        bundle_key: &str,
    ) -> Result<Option<RuntimePlatformProviderBundleResponse>, anyhow::Error> {
        let (client, path) = match self.machine_client() {
            Ok(client) => (
                client,
                format!("/v1/gateway/platform-provider-bundles/{bundle_key}"),
            ),
            Err(_) => (
                self.client(),
                format!("/v1/platform-provider-bundles/{bundle_key}"),
            ),
        };
        let resp = client.get(self.join_url(&path)).send().await?;
        let status = resp.status();

        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "hosted platform provider bundle fetch failed: status={status} body={body}"
            );
        }

        Ok(Some(
            resp.json::<RuntimePlatformProviderBundleResponse>().await?,
        ))
    }
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
    fn is_platform_scope_matches_platform() {
        assert!(is_platform_scope(Some("platform")));
    }

    #[test]
    fn is_platform_scope_matches_trimmed_platform() {
        assert!(is_platform_scope(Some("  platform  ")));
    }

    #[test]
    fn is_platform_scope_rejects_none() {
        assert!(!is_platform_scope(None));
    }

    #[test]
    fn is_platform_scope_rejects_empty() {
        assert!(!is_platform_scope(Some("")));
        assert!(!is_platform_scope(Some("   ")));
    }

    #[test]
    fn is_platform_scope_rejects_other_values() {
        assert!(!is_platform_scope(Some("org")));
        assert!(!is_platform_scope(Some("user")));
        assert!(!is_platform_scope(Some("Platform")));
    }

    #[test]
    fn global_default_provider_bundle_alias_is_stable() {
        assert_eq!(GLOBAL_DEFAULT_PROVIDER_BUNDLE_ALIAS, "global-default");
    }

    #[test]
    fn all_provider_target_ids_empty_registry() {
        let loaded = LoadedDeclarativeConfig::empty();
        let ids = all_provider_target_ids(&loaded);
        assert!(ids.is_empty());
    }

    #[test]
    fn runtime_platform_provider_bundle_response_deserialization() {
        let json = serde_json::json!({
            "bundle_key": "global-default",
            "provider_registry": {"targets": []},
            "_version": 1
        });
        let resp: RuntimePlatformProviderBundleResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.bundle_key, "global-default");
        assert_eq!(resp._version, 1);
    }

    #[test]
    fn validate_overlay_no_registry() {
        let loaded = LoadedDeclarativeConfig::empty();
        let result = validate_overlay_platform_secret_policy(
            "test",
            &std::collections::HashSet::new(),
            &loaded,
        );
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn resolve_hosted_secret_key_refs_none_sink() {
        let mut loaded = LoadedDeclarativeConfig::empty();
        let result = resolve_hosted_secret_key_refs(&None, &mut loaded).await;
        assert!(result.is_ok());
    }

    #[test]
    fn build_platform_provider_bundle_overlay_empty_targets() {
        let bundle = RuntimePlatformProviderBundleResponse {
            bundle_key: "test".to_string(),
            provider_registry: serde_json::json!({"targets": []}),
            _version: 1,
        };
        let _ = build_platform_provider_bundle_overlay(&bundle);
    }

    fn bundle_with_registry(registry: serde_json::Value) -> RuntimePlatformProviderBundleResponse {
        RuntimePlatformProviderBundleResponse {
            bundle_key: "global-default".to_string(),
            provider_registry: registry,
            _version: 7,
        }
    }

    fn byok_target_registry() -> serde_json::Value {
        serde_json::json!({
            "targets": [{
                "id": "openai-default",
                "provider": "openai",
                "model": "gpt-5.4-mini",
                "secret_key_ref": {"store": "OPENAI_API_KEY"}
            }]
        })
    }

    #[test]
    fn provider_bundle_accepts_store_backed_target() {
        validate_provider_bundle_registry("global-default", &byok_target_registry())
            .expect("a store-backed provider target is customer owned");
    }

    #[test]
    fn provider_bundle_accepts_empty_registry() {
        validate_provider_bundle_registry("global-default", &serde_json::json!({"targets": []}))
            .unwrap();
    }

    #[test]
    fn provider_bundle_rejects_literal_api_key() {
        let error = validate_provider_bundle_registry(
            "global-default",
            &serde_json::json!({
                "targets": [{"id": "openai-default", "api_key": "sk-literal-value"}]
            }),
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("literal api_key"), "{message}");
        assert!(message.contains("providers.targets[0]"), "{message}");
        assert!(!message.contains("sk-literal-value"), "{message}");
    }

    #[test]
    fn provider_bundle_allows_blank_api_key_field() {
        validate_provider_bundle_registry(
            "global-default",
            &serde_json::json!({"targets": [{"id": "openai-default", "api_key": "   "}]}),
        )
        .expect("a blank api_key carries no credential");
    }

    #[test]
    fn provider_bundle_rejects_authorization_header() {
        let error = validate_provider_bundle_registry(
            "global-default",
            &serde_json::json!({
                "targets": [{
                    "id": "openai-default",
                    "headers": {"Authorization": "Bearer sk-platform"}
                }]
            }),
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("credential-bearing header"), "{message}");
        assert!(message.contains("authorization"), "{message}");
        assert!(!message.contains("sk-platform"), "{message}");
    }

    #[test]
    fn provider_bundle_rejects_every_credential_bearing_header_name() {
        for header in CREDENTIAL_BEARING_HEADERS {
            let error = validate_provider_bundle_registry(
                "global-default",
                &serde_json::json!({
                    "targets": [{"id": "t", "headers": {header: "secret-value"}}]
                }),
            )
            .unwrap_err();
            assert!(
                error.to_string().contains(header),
                "{header} must be rejected"
            );
        }
    }

    #[test]
    fn provider_bundle_allows_non_credential_headers() {
        validate_provider_bundle_registry(
            "global-default",
            &serde_json::json!({
                "targets": [{
                    "id": "openai-default",
                    "headers": {"anthropic-version": "2023-06-01", "X-Trace": "on"}
                }]
            }),
        )
        .expect("routing headers stay allowed");
    }

    #[test]
    fn provider_bundle_allows_empty_credential_header_value() {
        validate_provider_bundle_registry(
            "global-default",
            &serde_json::json!({
                "targets": [{"id": "openai-default", "headers": {"Authorization": ""}}]
            }),
        )
        .expect("an empty header value carries no credential");
    }

    #[test]
    fn provider_bundle_rejects_platform_secret_scope() {
        let error = validate_provider_bundle_registry(
            "global-default",
            &serde_json::json!({
                "targets": [{
                    "id": "openai-default",
                    "secret_key_ref": {"scope": " platform ", "store": "OPENAI_API_KEY"}
                }]
            }),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("platform-scoped secret_key_ref"),
            "{error}"
        );
    }

    #[test]
    fn provider_bundle_allows_organization_secret_scope() {
        validate_provider_bundle_registry(
            "global-default",
            &serde_json::json!({
                "targets": [{
                    "id": "openai-default",
                    "secret_key_ref": {"scope": "organization", "store": "OPENAI_API_KEY"}
                }]
            }),
        )
        .expect("organization scope is customer owned");
    }

    #[test]
    fn provider_bundle_rejects_removed_managed_access_fields() {
        for field in REMOVED_MANAGED_ACCESS_FIELDS {
            let error = validate_provider_bundle_registry(
                "global-default",
                &serde_json::json!({"targets": [{"id": "t", field: true}]}),
            )
            .unwrap_err();
            let message = error.to_string();
            assert!(message.contains(field), "{message}");
            assert!(
                message.contains("removed managed-access field"),
                "{message}"
            );
        }
    }

    #[test]
    fn provider_bundle_rejects_managed_access_field_set_to_false() {
        for field in REMOVED_MANAGED_ACCESS_FIELDS {
            let error = validate_provider_bundle_registry(
                "global-default",
                &serde_json::json!({"targets": [{"id": "t", field: false}]}),
            )
            .unwrap_err();
            assert!(error.to_string().contains(field), "{error}");
        }
    }

    #[test]
    fn provider_bundle_rejects_credentials_nested_in_models() {
        let error = validate_provider_bundle_registry(
            "global-default",
            &serde_json::json!({
                "targets": [{
                    "id": "openai-default",
                    "models": [{"name": "gpt-5.4-mini", "api_key": "sk-nested"}]
                }]
            }),
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("literal api_key"), "{message}");
        assert!(
            message.contains("providers.targets[0].models[0]"),
            "{message}"
        );
    }

    #[test]
    fn provider_bundle_reports_the_bundle_key_in_the_error() {
        let error = validate_provider_bundle_registry(
            "legacy-bundle",
            &serde_json::json!({"targets": [{"id": "t", "use_byok": true}]}),
        )
        .unwrap_err();
        assert!(error.to_string().contains("legacy-bundle"), "{error}");
    }

    #[test]
    fn provider_bundle_overlay_build_rejects_credential_bearing_bundle() {
        let bundle = bundle_with_registry(serde_json::json!({
            "targets": [{"id": "openai-default", "api_key": "sk-literal"}]
        }));
        let error = build_platform_provider_bundle_overlay(&bundle).unwrap_err();
        assert!(error.to_string().contains("literal api_key"), "{error}");
    }

    #[test]
    fn provider_bundle_overlay_build_accepts_byok_bundle() {
        let bundle = bundle_with_registry(byok_target_registry());
        build_platform_provider_bundle_overlay(&bundle)
            .expect("a store-backed bundle must still load");
    }
}

#[doc(hidden)]
pub async fn resolve_hosted_secret_key_refs(
    sink: &Option<EventSink>,
    loaded: &mut LoadedDeclarativeConfig,
) -> Result<(), anyhow::Error> {
    let Some(sink) = sink.as_ref() else {
        return Ok(());
    };

    // Reject any target that uses keychain refs in hosted mode.
    if let Some(registry) = loaded.provider_registry.as_ref() {
        for target in &registry.targets {
            if let Some(ref secret_ref) = target.secret_key_ref {
                if secret_ref.is_keychain_ref() {
                    anyhow::bail!(
                        "hosted gateway: provider target '{}' uses secret_key_ref.keychain which is not supported in hosted mode. \
                         Use secret_key_ref.store or secret_key_ref.env instead.",
                        target.id
                    );
                }
            }
        }
    }

    let provider_bundle = sink
        .fetch_org_platform_provider_bundle(GLOBAL_DEFAULT_PROVIDER_BUNDLE_ALIAS)
        .await
        .map_err(|error| {
            anyhow::anyhow!("hosted gateway: platform provider bundle fetch failed: {error}")
        })?;

    if let Some(provider_bundle) = provider_bundle {
        let bundle_overlay = build_platform_provider_bundle_overlay(&provider_bundle)?;
        let protected_target_ids = all_provider_target_ids(&bundle_overlay);
        validate_overlay_platform_secret_policy("hosted config", &protected_target_ids, loaded)?;
        *loaded = if loaded.raw_yaml.trim().is_empty() {
            bundle_overlay
        } else {
            LoadedDeclarativeConfig::merged_with_overlay(&bundle_overlay, loaded)
                .map_err(|error| anyhow::anyhow!("hosted config merge failed: {error}"))?
        };
    }

    let names: Vec<String> = loaded
        .provider_registry
        .as_ref()
        .map(|registry| {
            registry
                .targets
                .iter()
                .filter_map(|target| target.secret_key_ref.as_ref())
                .filter_map(|reference| reference.store_name().map(ToString::to_string))
                .collect()
        })
        .unwrap_or_default();

    if names.is_empty() {
        return Ok(());
    }

    tracing::debug!(
        ref_count = names.len(),
        "hosted gateway: deferring secret_key_ref.store resolution to request-time access preflight"
    );

    Ok(())
}
