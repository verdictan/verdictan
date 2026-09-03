// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Region-aware provider endpoint selection.
//!
//! selection consumes only region / data-residency identity on
//! `ProviderTarget`. It does not read unread auto-routing, A/B, shadow,
//! health-threshold, price-ceiling, or provider-rate-limit config fields.
//! Absence of an in-region endpoint denies the request (fail closed).
//!
//! region and privacy (ZDR) helpers feed the provider-pool
//! eligibility filter in `auto_provider`. Pool selection pins one target and
//! never invents alternate-provider fallback after a primary-path failure.
//!
//! [`provider_matches_region`] is the single region-eligibility predicate in
//! the crate. `providers::filter_by_region` applies it on the live
//! `providers.routing.require_region` path and `auto_provider` applies it to
//! provider-pool eligibility, so the two cannot drift apart.

use super::providers::ProviderTarget;

/// Region / data-residency match used by the live region filter and the
/// provider pool.
///
/// A declared `data_residency` block is authoritative. It is the operator's
/// statement about where the endpoint keeps request data, so a broader `region`
/// label must not widen it back out — otherwise the key could only ever add
/// eligibility and would never constrain routing. Targets without a residency
/// block keep the historical `region` comparison.
pub(crate) fn provider_matches_region(target: &ProviderTarget, publication_region: &str) -> bool {
    if let Some(residency) = target.data_residency.as_ref() {
        return residency
            .regions
            .iter()
            .any(|region| region.eq_ignore_ascii_case(publication_region));
    }
    target
        .region
        .as_deref()
        .is_some_and(|region| region.eq_ignore_ascii_case(publication_region))
}

/// Privacy (ZDR) eligibility for the provider-pool model.
///
/// When `require_zdr` is false every target remains eligible on the privacy
/// axis. When true, only targets that declare `zdr = true` pass.
pub(crate) fn provider_matches_privacy(target: &ProviderTarget, require_zdr: bool) -> bool {
    !require_zdr || target.zdr
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
    use crate::gateway::providers::DataResidencyPolicy;
    use std::collections::HashMap;
    use std::time::Duration;

    fn residency(regions: &[&str]) -> DataResidencyPolicy {
        DataResidencyPolicy {
            regions: regions.iter().map(|r| (*r).to_string()).collect(),
            data_center_locations: Vec::new(),
            sovereignty_compliant: true,
        }
    }

    fn sample_target(region: Option<&str>) -> ProviderTarget {
        ProviderTarget {
            id: "t1".into(),
            provider: "openai".into(),
            model: "gpt-4".into(),
            execution_target: None,
            mcp_bridge: None,
            description: None,
            base_url: "https://api.openai.com".into(),
            api_key: "k".into(),
            api_key_header: "Authorization".into(),
            api_key_prefix: "Bearer ".into(),
            secret_key_ref: None,
            path_template: None,
            headers: HashMap::new(),
            timeout: Duration::from_secs(30),
            stream_timeout: None,
            max_context_tokens: None,
            max_messages: None,
            data_policy: None,
            pricing: None,
            models: vec![],
            data_collection: None,
            zdr: false,
            region: region.map(str::to_string),
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
    fn region_label_matches_without_residency_block() {
        let target = sample_target(Some("eu-west"));
        assert!(provider_matches_region(&target, "eu-west"));
        assert!(!provider_matches_region(&target, "us-east"));
    }

    #[test]
    fn target_without_region_or_residency_is_never_eligible() {
        let target = sample_target(None);
        assert!(!provider_matches_region(&target, "eu-west"));
    }

    #[test]
    fn residency_regions_make_a_target_eligible() {
        let mut target = sample_target(None);
        target.data_residency = Some(residency(&["eu-west", "eu-central"]));
        assert!(provider_matches_region(&target, "eu-west"));
        assert!(provider_matches_region(&target, "EU-CENTRAL"));
        assert!(!provider_matches_region(&target, "us-east"));
    }

    #[test]
    fn residency_block_overrides_a_wider_region_label() {
        // The residency block is the compliance statement. A `region` label that
        // names a different region must not put the target back in play.
        let mut target = sample_target(Some("us-east"));
        target.data_residency = Some(residency(&["eu-west"]));
        assert!(
            !provider_matches_region(&target, "us-east"),
            "a residency policy that excludes the region must win over the region label"
        );
        assert!(provider_matches_region(&target, "eu-west"));
    }

    #[test]
    fn empty_residency_region_list_fails_closed() {
        let mut target = sample_target(Some("eu-west"));
        target.data_residency = Some(residency(&[]));
        assert!(!provider_matches_region(&target, "eu-west"));
    }

    #[test]
    fn privacy_helper_requires_zdr_when_requested() {
        let mut target = sample_target(Some("eu-west"));
        target.zdr = false;
        assert!(provider_matches_privacy(&target, false));
        assert!(!provider_matches_privacy(&target, true));
        target.zdr = true;
        assert!(provider_matches_privacy(&target, true));
    }
}
