// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::collections::HashSet;

use serde::Serialize;

use super::provider_endpoint_selection::{provider_matches_privacy, provider_matches_region};
use super::provider_metrics::ProviderMetrics;
use super::providers::ProviderTarget;

/// Configuration for the `auto` composite routing strategy.
///
/// Only `max_price_per_1m_tokens` acts as an eligibility ceiling.
/// When all candidates are excluded the router returns an empty set
/// (typed `no_eligible_provider`) rather than silently falling back.
///
//: selection is request-pinned to a single target with
/// durable [`SelectionEvidence`]. Network/provider failure of that target
/// must surface the primary-path error — this module never schedules
/// alternate-provider fallback.
#[derive(Debug, Clone)]
pub struct AutoRoutingConfig {
    pub cost_weight: f64,
    pub latency_weight: f64,
    pub max_price_per_1m_tokens: Option<f64>,
}

impl Default for AutoRoutingConfig {
    fn default() -> Self {
        Self {
            cost_weight: 0.5,
            latency_weight: 0.5,
            max_price_per_1m_tokens: None,
        }
    }
}

/// Keys consumed by the `auto:` virtual provider.
pub(crate) const CONSUMED_AUTO_FIELDS: &[&str] = &["enabled", "name", "description", "routing"];

/// Keys consumed by `auto.routing`.
///
/// `max_price_per_1m_tokens` is the only eligibility ceiling with dispatch
/// effect. Other historical routing/health/A/B/fallback/shadow/rate-limit
/// keys are rejected rather than silently retained.
pub(crate) const CONSUMED_AUTO_ROUTING_FIELDS: &[&str] =
    &["cost_weight", "latency_weight", "max_price_per_1m_tokens"];

/// Named unread / removed `auto.routing` fields. Presence is a load-time error.
///
/// Covers the categories: fallback, health, A/B, shadow,
/// provider-rate-limit, plus prior inert measurement fields.
pub(crate) const REMOVED_AUTO_ROUTING_FIELDS: &[&str] = &[
    // Fallback (no alternate-provider dispatch from auto config)
    "fallback_enabled",
    "allow_fallbacks",
    "max_fallback_attempts",
    // Health (auto scoring does not consume unhealthy thresholds)
    "unhealthy_threshold",
    "unhealthy_window_seconds",
    "measurement_window_seconds",
    "min_sample_count",
    "health_check",
    "health",
    // A/B / canary (no auto-section variant dispatch)
    "ab_test",
    "ab_testing",
    "a_b",
    "variants",
    "sticky_by",
    "traffic_split",
    "canary",
    "canary_percent",
    // Shadow (shadow lives under providers.traffic_mirror / runtime settings)
    "shadow",
    "shadow_enabled",
    "shadow_routing",
    "traffic_mirror",
    // Provider-scoped rate limits (not enforced from auto.routing)
    "rate_limit",
    "rate_limits",
    "provider_rate_limit",
    "rpm",
    "tpm",
    "max_parallel_requests",
];

/// Top-level `auto:` virtual provider config.
#[derive(Debug, Clone)]
pub struct AutoProviderConfig {
    pub enabled: bool,
    pub name: String,
    pub description: Option<String>,
    pub routing: AutoRoutingConfig,
}

impl Default for AutoProviderConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            name: "auto".to_string(),
            description: Some(
                "Cheapest and fastest available provider, chosen automatically".to_string(),
            ),
            routing: AutoRoutingConfig::default(),
        }
    }
}

fn reject_unknown_keys(
    object: &serde_json::Map<String, serde_json::Value>,
    allowed: &[&str],
    path: &str,
) -> Result<(), String> {
    for key in object.keys() {
        if !allowed.iter().any(|allowed_key| allowed_key == key) {
            return Err(format!(
                "{path}.{key}: unknown or unread field — allowed keys: {}",
                allowed.join(", ")
            ));
        }
    }
    Ok(())
}

/// Parse the `auto:` section from root config JSON.
///
/// Returns an error if removed or unknown fields are present. Every accepted
/// key must have dispatch behavior; silent unread retention is forbidden
///.
pub fn parse_auto(root: &serde_json::Value) -> Result<AutoProviderConfig, String> {
    let section = match root.get("auto") {
        Some(v) if v.is_object() => v,
        _ => return Ok(AutoProviderConfig::default()),
    };

    let section_object = section
        .as_object()
        .ok_or_else(|| "auto: must be an object".to_string())?;
    reject_unknown_keys(section_object, CONSUMED_AUTO_FIELDS, "auto")?;

    let enabled = section
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let name = section
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("auto")
        .to_string();
    let description = section
        .get("description")
        .and_then(|v| v.as_str())
        .map(String::from);

    let routing = if let Some(r) = section.get("routing") {
        let routing_object = r
            .as_object()
            .ok_or_else(|| "auto.routing: must be an object".to_string())?;

        // Named removed categories first (clearer operator message).
        for field in REMOVED_AUTO_ROUTING_FIELDS {
            if routing_object.contains_key(*field) {
                return Err(format!(
                    "auto.routing.{field} has been removed; it had no runtime effect"
                ));
            }
        }
        // Fail closed on any other unread key.
        reject_unknown_keys(routing_object, CONSUMED_AUTO_ROUTING_FIELDS, "auto.routing")?;

        let mut cost_weight = r.get("cost_weight").and_then(|v| v.as_f64()).unwrap_or(0.5);
        let mut latency_weight = r
            .get("latency_weight")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.5);

        let sum = cost_weight + latency_weight;
        if (sum - 1.0).abs() > 0.01 {
            tracing::warn!(
                cost_weight,
                latency_weight,
                "auto routing weights do not sum to 1.0; clamping"
            );
            let total = cost_weight + latency_weight;
            if total > 0.0 {
                cost_weight /= total;
                latency_weight /= total;
            } else {
                cost_weight = 0.5;
                latency_weight = 0.5;
            }
        }

        AutoRoutingConfig {
            cost_weight,
            latency_weight,
            max_price_per_1m_tokens: r.get("max_price_per_1m_tokens").and_then(|v| v.as_f64()),
        }
    } else {
        AutoRoutingConfig::default()
    };

    Ok(AutoProviderConfig {
        enabled,
        name,
        description,
        routing,
    })
}

/// Select and rank provider targets using composite cost+latency scoring.
///
/// Returns candidate targets sorted ascending by composite score (best first).
/// Targets whose price exceeds `max_price_per_1m_tokens` are excluded.
/// When pricing data is unavailable for a target and a ceiling is configured,
/// the target is excluded (fail closed).
/// If all targets are excluded, returns an empty vec — the caller must handle
/// the `no_eligible_provider` condition.
///
/// This is the legacy 3-argument entry point (no usage-authorization exclusion). It
/// is preserved byte-for-byte for benches and existing callers/tests, and simply
/// delegates to [`score_targets_with_denied`] with no denied set.
pub fn score_targets<'a>(
    targets: &'a [ProviderTarget],
    routing: &AutoRoutingConfig,
    metrics: &ProviderMetrics,
) -> Vec<&'a ProviderTarget> {
    score_targets_with_denied(targets, routing, metrics, None)
}

/// Same as [`score_targets`], but additionally excludes any candidate whose
/// provider-target id is in `denied_target_ids`. The
/// denied set is produced by a READ-ONLY usage-authorization evaluate per candidate
/// (`populate_ua_denied_target_ids`). Passing `None` (or an empty set) is a
/// no-op, so legacy selection is byte-identical.
pub fn score_targets_with_denied<'a>(
    targets: &'a [ProviderTarget],
    routing: &AutoRoutingConfig,
    metrics: &ProviderMetrics,
    denied_target_ids: Option<&std::collections::HashSet<String>>,
) -> Vec<&'a ProviderTarget> {
    if targets.is_empty() {
        return Vec::new();
    }

    let epsilon: f64 = 1e-9;

    struct Candidate<'b> {
        target: &'b ProviderTarget,
        cost: f64,
        latency: f64,
    }

    let mut candidates: Vec<Candidate<'a>> = Vec::with_capacity(targets.len());
    for target in targets {
        // exclude candidates the subject is not allowed to
        // use, as decided upstream by a READ-ONLY usage-authorization evaluate
        // (populate_ua_denied_target_ids). An empty/None set is a no-op, so every
        // non-UA / legacy selection path stays byte-identical.
        if denied_target_ids.is_some_and(|denied| denied.contains(&target.id)) {
            continue;
        }
        // Effective cost: average of input and output price per 1M tokens.
        let cost = target
            .pricing
            .as_ref()
            .map(|p| (p.input_price_per_million + p.output_price_per_million) / 2.0);

        // Filter by max_price ceiling — fail closed when pricing is unavailable.
        if let Some(max_price) = routing.max_price_per_1m_tokens {
            match cost {
                Some(c) if c > max_price => continue,
                None => continue, // no pricing data → excluded
                _ => {}
            }
        }

        let cost_val = cost.unwrap_or(0.0);

        // Latency: use p50 TTFT when available, else 0.
        let latency = metrics
            .percentile_ttft(&target.id, super::providers::Percentile::P50)
            .unwrap_or(0.0);

        candidates.push(Candidate {
            target,
            cost: cost_val,
            latency,
        });
    }

    // No fallback: empty means no_eligible_provider.
    if candidates.is_empty() {
        return Vec::new();
    }

    // Compute min/max for normalisation.
    let min_cost = candidates
        .iter()
        .map(|c| c.cost)
        .fold(f64::INFINITY, f64::min);
    let max_cost = candidates
        .iter()
        .map(|c| c.cost)
        .fold(f64::NEG_INFINITY, f64::max);
    let min_latency = candidates
        .iter()
        .map(|c| c.latency)
        .fold(f64::INFINITY, f64::min);
    let max_latency = candidates
        .iter()
        .map(|c| c.latency)
        .fold(f64::NEG_INFINITY, f64::max);

    let cost_range = max_cost - min_cost + epsilon;
    let latency_range = max_latency - min_latency + epsilon;

    // Score and sort ascending with deterministic id tie-break.
    let mut scored: Vec<(f64, &'a ProviderTarget)> = candidates
        .iter()
        .map(|c| {
            let norm_cost = (c.cost - min_cost) / cost_range;
            let norm_latency = (c.latency - min_latency) / latency_range;
            let score = routing.cost_weight * norm_cost + routing.latency_weight * norm_latency;
            (score, c.target)
        })
        .collect();

    scored.sort_by(
        |a, b| match a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal) {
            std::cmp::Ordering::Equal => a.1.id.cmp(&b.1.id),
            other => other,
        },
    );
    scored.into_iter().map(|(_, t)| t).collect()
}

/// Request-scoped eligibility constraints for the provider-pool model.
#[derive(Debug, Clone, Default)]
pub struct ProviderPoolConstraints {
    /// Required publication / data-residency region. When set, only in-region
    /// endpoints remain eligible.
    pub publication_region: Option<String>,
    /// When true, only ZDR-capable targets remain eligible.
    pub require_zdr: bool,
    /// Capability tokens the selected target (or nested model entry) must advertise.
    pub required_capabilities: Vec<String>,
    /// Usage-authorization / policy denials — excluded before scoring.
    pub denied_target_ids: Option<HashSet<String>>,
}

/// Per-candidate scorecard row retained in durable selection evidence.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CandidateScoreEvidence {
    pub target_id: String,
    pub provider: String,
    pub model: String,
    pub score: Option<f64>,
    pub cost: Option<f64>,
    pub latency: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclusion_reason: Option<&'static str>,
}

/// Durable, request-pinned provider-pool selection evidence.
///
/// `alternate_provider_fallback` is always `false`: the pool model pins one
/// target and never schedules an alternate provider after selection.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SelectionEvidence {
    pub decision_id: String,
    pub request_id: String,
    pub selected_target_id: String,
    pub selected_provider: String,
    pub selected_model: String,
    pub composite_score: f64,
    /// Stable decision basis for control-plane `route_decision_log` mapping.
    pub decision_basis: &'static str,
    pub candidates: Vec<CandidateScoreEvidence>,
    pub alternate_provider_fallback: bool,
    pub pinned: bool,
}

/// Request-pinned provider-pool selection outcome.
#[derive(Debug, Clone)]
pub struct PinnedProviderSelection<'a> {
    pub target: &'a ProviderTarget,
    pub evidence: SelectionEvidence,
}

/// Empty eligible set after credential / region / privacy / budget / capability filters.
#[derive(Debug, Clone)]
pub struct NoEligibleProvider {
    pub evidence: SelectionEvidence,
}

/// Decision basis recorded for deterministic pool scoring (maps to DB check).
pub const PROVIDER_POOL_DECISION_BASIS: &str = "scorecard";

/// Credential availability: resolved key material or an unresolved secret ref
/// that the connected/local runtime can still satisfy.
pub fn target_has_credential(target: &ProviderTarget) -> bool {
    !target.api_key.trim().is_empty() || target.secret_key_ref.is_some() || target.oauth2.is_some()
}

/// Capability match against nested model entries, falling back to accepting an
/// empty requirement set. When requirements are non-empty and the target has
/// no nested models, the target is ineligible (fail closed).
pub fn target_meets_capabilities(target: &ProviderTarget, required: &[String]) -> bool {
    if required.is_empty() {
        return true;
    }
    if target.models.is_empty() {
        return false;
    }
    target.models.iter().any(|entry| {
        entry.enabled
            && required.iter().all(|need| {
                entry
                    .supported_features
                    .iter()
                    .any(|have| have.eq_ignore_ascii_case(need))
            })
    })
}

fn exclusion_reason_for_target(
    target: &ProviderTarget,
    routing: &AutoRoutingConfig,
    constraints: &ProviderPoolConstraints,
) -> Option<&'static str> {
    if constraints
        .denied_target_ids
        .as_ref()
        .is_some_and(|denied| denied.contains(&target.id))
    {
        return Some("denied_by_policy");
    }
    if !target_has_credential(target) {
        return Some("credential_unavailable");
    }
    if let Some(region) = constraints.publication_region.as_deref() {
        if !provider_matches_region(target, region) {
            return Some("region_privacy_constraint");
        }
    }
    if !provider_matches_privacy(target, constraints.require_zdr) {
        return Some("region_privacy_constraint");
    }
    if !target_meets_capabilities(target, &constraints.required_capabilities) {
        return Some("capability_unsatisfied");
    }
    if let Some(max_price) = routing.max_price_per_1m_tokens {
        let cost = target
            .pricing
            .as_ref()
            .map(|p| (p.input_price_per_million + p.output_price_per_million) / 2.0);
        match cost {
            Some(c) if c > max_price => return Some("budget_ceiling"),
            None => return Some("budget_ceiling"),
            _ => {}
        }
    }
    None
}

fn empty_selection_evidence(
    request_id: &str,
    candidates: Vec<CandidateScoreEvidence>,
) -> SelectionEvidence {
    SelectionEvidence {
        decision_id: format!("vdt_decision_{request_id}"),
        request_id: request_id.to_string(),
        selected_target_id: String::new(),
        selected_provider: String::new(),
        selected_model: String::new(),
        composite_score: 0.0,
        decision_basis: PROVIDER_POOL_DECISION_BASIS,
        candidates,
        alternate_provider_fallback: false,
        pinned: false,
    }
}

/// Select exactly one provider-pool target for a request.
///
/// Filters by credential availability, region/privacy, budget ceiling, and
/// capability requirements; scores the survivors deterministically; pins the
/// single best target; and returns durable [`SelectionEvidence`]. An empty
/// eligible set yields [`NoEligibleProvider`] — callers must not invent an
/// alternate provider.
fn select_provider_pool<'a>(
    targets: &'a [ProviderTarget],
    routing: &AutoRoutingConfig,
    metrics: &ProviderMetrics,
    constraints: &ProviderPoolConstraints,
    request_id: &str,
) -> Result<PinnedProviderSelection<'a>, Box<NoEligibleProvider>> {
    let mut considered: Vec<CandidateScoreEvidence> = Vec::with_capacity(targets.len());
    let mut eligible: Vec<&'a ProviderTarget> = Vec::new();

    for target in targets {
        if let Some(reason) = exclusion_reason_for_target(target, routing, constraints) {
            considered.push(CandidateScoreEvidence {
                target_id: target.id.clone(),
                provider: target.provider.clone(),
                model: target.model.clone(),
                score: None,
                cost: None,
                latency: None,
                exclusion_reason: Some(reason),
            });
            continue;
        }
        eligible.push(target);
    }

    if eligible.is_empty() {
        return Err(Box::new(NoEligibleProvider {
            evidence: empty_selection_evidence(request_id, considered),
        }));
    }

    let epsilon = 1e-9;
    let costs: Vec<f64> = eligible
        .iter()
        .map(|t| {
            t.pricing
                .as_ref()
                .map(|p| (p.input_price_per_million + p.output_price_per_million) / 2.0)
                .unwrap_or(0.0)
        })
        .collect();
    let latencies: Vec<f64> = eligible
        .iter()
        .map(|t| {
            metrics
                .percentile_ttft(&t.id, super::providers::Percentile::P50)
                .unwrap_or(0.0)
        })
        .collect();
    let min_cost = costs.iter().copied().fold(f64::INFINITY, f64::min);
    let max_cost = costs.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let min_latency = latencies.iter().copied().fold(f64::INFINITY, f64::min);
    let max_latency = latencies.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let cost_range = max_cost - min_cost + epsilon;
    let latency_range = max_latency - min_latency + epsilon;

    let mut ranked: Vec<(f64, usize)> = eligible
        .iter()
        .enumerate()
        .map(|(idx, _)| {
            let cost = costs[idx];
            let latency = latencies[idx];
            let score = routing.cost_weight * ((cost - min_cost) / cost_range)
                + routing.latency_weight * ((latency - min_latency) / latency_range);
            (score, idx)
        })
        .collect();
    ranked.sort_by(
        |a, b| match a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal) {
            std::cmp::Ordering::Equal => eligible[a.1].id.cmp(&eligible[b.1].id),
            other => other,
        },
    );

    for &(score, idx) in &ranked {
        let target = eligible[idx];
        considered.push(CandidateScoreEvidence {
            target_id: target.id.clone(),
            provider: target.provider.clone(),
            model: target.model.clone(),
            score: Some(score),
            cost: Some(costs[idx]),
            latency: Some(latencies[idx]),
            exclusion_reason: None,
        });
    }

    let (selected_score, selected_idx) = ranked[0];
    let selected = eligible[selected_idx];

    let evidence = SelectionEvidence {
        decision_id: format!("vdt_decision_{request_id}"),
        request_id: request_id.to_string(),
        selected_target_id: selected.id.clone(),
        selected_provider: selected.provider.clone(),
        selected_model: selected.model.clone(),
        composite_score: selected_score,
        decision_basis: PROVIDER_POOL_DECISION_BASIS,
        candidates: considered,
        alternate_provider_fallback: false,
        pinned: true,
    };

    Ok(PinnedProviderSelection {
        target: selected,
        evidence,
    })
}

/// Indices of the request-pinned target only — never expands into alternate fallbacks.
fn pinned_target_indices(
    registry_targets: &[ProviderTarget],
    selection: &PinnedProviderSelection<'_>,
) -> Vec<usize> {
    registry_targets
        .iter()
        .enumerate()
        .filter_map(|(idx, target)| (target.id == selection.target.id).then_some(idx))
        .collect()
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
    fn parse_auto_defaults_when_missing() {
        let root = json!({"providers": []});
        let config = parse_auto(&root).unwrap();
        assert!(config.enabled);
        assert_eq!(config.name, "auto");
        assert!(config.description.is_some());
        assert!((config.routing.cost_weight - 0.5).abs() < f64::EPSILON);
        assert!((config.routing.latency_weight - 0.5).abs() < f64::EPSILON);
        assert!(config.routing.max_price_per_1m_tokens.is_none());
    }

    #[test]
    fn parse_auto_disabled() {
        let root = json!({"auto": {"enabled": false}});
        let config = parse_auto(&root).unwrap();
        assert!(!config.enabled);
    }

    #[test]
    fn parse_auto_custom_name() {
        let root = json!({"auto": {"name": "smart-router"}});
        let config = parse_auto(&root).unwrap();
        assert_eq!(config.name, "smart-router");
    }

    #[test]
    fn parse_auto_custom_routing() {
        let root = json!({
            "auto": {
                "routing": {
                    "cost_weight": 0.7,
                    "latency_weight": 0.3,
                    "max_price_per_1m_tokens": 10.0
                }
            }
        });
        let config = parse_auto(&root).unwrap();
        assert!((config.routing.cost_weight - 0.7).abs() < f64::EPSILON);
        assert!((config.routing.latency_weight - 0.3).abs() < f64::EPSILON);
        assert_eq!(config.routing.max_price_per_1m_tokens, Some(10.0));
    }

    #[test]
    fn parse_auto_rejects_removed_fallback_enabled() {
        let root = json!({
            "auto": { "routing": { "fallback_enabled": true } }
        });
        let err = parse_auto(&root).unwrap_err();
        assert!(err.contains("fallback_enabled"), "error: {err}");
        assert!(err.contains("removed"), "error: {err}");
    }

    #[test]
    fn parse_auto_rejects_removed_unhealthy_threshold() {
        let root = json!({
            "auto": { "routing": { "unhealthy_threshold": 5 } }
        });
        let err = parse_auto(&root).unwrap_err();
        assert!(err.contains("unhealthy_threshold"), "error: {err}");
    }

    #[test]
    fn parse_auto_rejects_removed_unhealthy_window_seconds() {
        let root = json!({
            "auto": { "routing": { "unhealthy_window_seconds": 120 } }
        });
        let err = parse_auto(&root).unwrap_err();
        assert!(err.contains("unhealthy_window_seconds"), "error: {err}");
    }

    #[test]
    fn parse_auto_rejects_ab_shadow_and_rate_limit_fields() {
        for field in &[
            "ab_test",
            "shadow_routing",
            "provider_rate_limit",
            "measurement_window_seconds",
            "min_sample_count",
            "allow_fallbacks",
        ] {
            let root = json!({
                "auto": { "routing": { field.to_string(): true } }
            });
            let err = parse_auto(&root).unwrap_err();
            assert!(
                err.contains(field),
                "expected rejection of {field}, got: {err}"
            );
        }
    }

    #[test]
    fn parse_auto_rejects_unknown_auto_and_routing_keys() {
        let unknown_auto = json!({ "auto": { "secret_knob": true } });
        let err = parse_auto(&unknown_auto).unwrap_err();
        assert!(err.contains("secret_knob"), "error: {err}");
        assert!(err.contains("unknown or unread"), "error: {err}");

        let unknown_routing = json!({
            "auto": { "routing": { "mystery_weight": 0.2 } }
        });
        let err = parse_auto(&unknown_routing).unwrap_err();
        assert!(err.contains("mystery_weight"), "error: {err}");
    }

    #[test]
    fn parse_auto_weights_clamped_when_not_summing_to_one() {
        let root = json!({
            "auto": {
                "routing": {
                    "cost_weight": 3.0,
                    "latency_weight": 7.0
                }
            }
        });
        let config = parse_auto(&root).unwrap();
        assert!((config.routing.cost_weight - 0.3).abs() < 0.01);
        assert!((config.routing.latency_weight - 0.7).abs() < 0.01);
    }

    #[test]
    fn parse_auto_zero_weights_fallback() {
        let root = json!({
            "auto": {
                "routing": {
                    "cost_weight": 0.0,
                    "latency_weight": 0.0
                }
            }
        });
        let config = parse_auto(&root).unwrap();
        assert!((config.routing.cost_weight - 0.5).abs() < f64::EPSILON);
        assert!((config.routing.latency_weight - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn auto_routing_config_default() {
        let config = AutoRoutingConfig::default();
        assert!((config.cost_weight - 0.5).abs() < f64::EPSILON);
        assert!((config.latency_weight - 0.5).abs() < f64::EPSILON);
        assert!(config.max_price_per_1m_tokens.is_none());
    }

    #[test]
    fn auto_provider_config_default() {
        let config = AutoProviderConfig::default();
        assert!(config.enabled);
        assert_eq!(config.name, "auto");
        assert!(config.description.is_some());
    }

    #[test]
    fn score_targets_empty_returns_empty() {
        let targets: Vec<ProviderTarget> = vec![];
        let routing = AutoRoutingConfig::default();
        let metrics = ProviderMetrics::new(60, 1);
        let result = score_targets(&targets, &routing, &metrics);
        assert!(result.is_empty());
    }

    fn make_pricing(input: f64, output: f64) -> super::super::providers::ProviderPricing {
        super::super::providers::ProviderPricing {
            input_price_per_million: input,
            output_price_per_million: output,
            cached_input_price_per_million: None,
            input_multiplier: None,
            cached_input_multiplier: None,
            output_multiplier: None,
        }
    }

    #[test]
    fn score_targets_all_over_budget_returns_empty() {
        let targets = vec![ProviderTarget {
            id: "expensive".into(),
            pricing: Some(make_pricing(100.0, 100.0)),
            ..Default::default()
        }];
        let routing = AutoRoutingConfig {
            max_price_per_1m_tokens: Some(1.0),
            ..Default::default()
        };
        let metrics = ProviderMetrics::new(60, 1);
        let result = score_targets(&targets, &routing, &metrics);
        assert!(result.is_empty(), "must return empty when all over budget");
    }

    #[test]
    fn score_targets_no_pricing_excluded_when_ceiling_set() {
        let targets = vec![ProviderTarget {
            id: "unpriced".into(),
            pricing: None,
            ..Default::default()
        }];
        let routing = AutoRoutingConfig {
            max_price_per_1m_tokens: Some(10.0),
            ..Default::default()
        };
        let metrics = ProviderMetrics::new(60, 1);
        let result = score_targets(&targets, &routing, &metrics);
        assert!(result.is_empty(), "unpriced must be excluded (fail closed)");
    }

    #[test]
    fn score_targets_eligible_single() {
        let targets = vec![ProviderTarget {
            id: "cheap".into(),
            pricing: Some(make_pricing(0.5, 0.5)),
            ..Default::default()
        }];
        let routing = AutoRoutingConfig {
            max_price_per_1m_tokens: Some(10.0),
            ..Default::default()
        };
        let metrics = ProviderMetrics::new(60, 1);
        let result = score_targets(&targets, &routing, &metrics);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "cheap");
    }

    // ── increment 3c: read-only UA denied-candidate exclusion ────────

    #[test]
    fn score_targets_excludes_denied_candidate() {
        let targets = vec![
            ProviderTarget {
                id: "cheap".into(),
                pricing: Some(make_pricing(0.5, 0.5)),
                ..Default::default()
            },
            ProviderTarget {
                id: "premium".into(),
                pricing: Some(make_pricing(2.0, 2.0)),
                ..Default::default()
            },
        ];
        let routing = AutoRoutingConfig {
            max_price_per_1m_tokens: Some(10.0),
            ..Default::default()
        };
        let metrics = ProviderMetrics::new(60, 1);

        // No denial: both eligible.
        let all = score_targets(&targets, &routing, &metrics);
        assert_eq!(all.len(), 2);

        // Deny the cheapest (top pick): only the allowed candidate remains.
        let denied: std::collections::HashSet<String> = ["cheap".to_string()].into_iter().collect();
        let result = score_targets_with_denied(&targets, &routing, &metrics, Some(&denied));
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].id, "premium",
            "a UA-denied candidate must be excluded from selection"
        );
    }

    #[test]
    fn score_targets_all_denied_returns_empty() {
        let targets = vec![
            ProviderTarget {
                id: "a".into(),
                pricing: Some(make_pricing(0.5, 0.5)),
                ..Default::default()
            },
            ProviderTarget {
                id: "b".into(),
                pricing: Some(make_pricing(0.6, 0.6)),
                ..Default::default()
            },
        ];
        let routing = AutoRoutingConfig::default();
        let metrics = ProviderMetrics::new(60, 1);
        let denied: std::collections::HashSet<String> =
            ["a".to_string(), "b".to_string()].into_iter().collect();
        let result = score_targets_with_denied(&targets, &routing, &metrics, Some(&denied));
        assert!(
            result.is_empty(),
            "all-denied candidates yield no eligible target"
        );
    }

    #[test]
    fn score_targets_empty_denied_set_is_no_op() {
        let targets = vec![
            ProviderTarget {
                id: "cheap".into(),
                pricing: Some(make_pricing(0.5, 0.5)),
                ..Default::default()
            },
            ProviderTarget {
                id: "premium".into(),
                pricing: Some(make_pricing(2.0, 2.0)),
                ..Default::default()
            },
        ];
        let routing = AutoRoutingConfig::default();
        let metrics = ProviderMetrics::new(60, 1);
        let empty: std::collections::HashSet<String> = std::collections::HashSet::new();
        let with_empty = score_targets_with_denied(&targets, &routing, &metrics, Some(&empty));
        let with_none = score_targets(&targets, &routing, &metrics);
        assert_eq!(with_empty.len(), with_none.len());
        assert_eq!(with_empty.len(), 2);
    }

    // ──: provider-pool selection ────────────────────────────

    #[test]
    fn select_provider_pool_pins_cheapest_and_records_evidence() {
        let targets = vec![
            ProviderTarget {
                id: "premium".into(),
                provider: "openai".into(),
                model: "gpt-4".into(),
                api_key: "sk-premium".into(),
                pricing: Some(make_pricing(5.0, 5.0)),
                region: Some("us".into()),
                ..Default::default()
            },
            ProviderTarget {
                id: "cheap".into(),
                provider: "openai".into(),
                model: "gpt-4o-mini".into(),
                api_key: "sk-cheap".into(),
                pricing: Some(make_pricing(0.5, 0.5)),
                region: Some("us".into()),
                ..Default::default()
            },
        ];
        let routing = AutoRoutingConfig {
            cost_weight: 1.0,
            latency_weight: 0.0,
            max_price_per_1m_tokens: Some(10.0),
        };
        let metrics = ProviderMetrics::new(60, 1);
        let constraints = ProviderPoolConstraints {
            publication_region: Some("us".into()),
            ..Default::default()
        };
        let pinned = select_provider_pool(&targets, &routing, &metrics, &constraints, "req-1")
            .expect("eligible pool");
        assert_eq!(pinned.target.id, "cheap");
        assert!(pinned.evidence.pinned);
        assert!(!pinned.evidence.alternate_provider_fallback);
        assert_eq!(pinned.evidence.decision_basis, PROVIDER_POOL_DECISION_BASIS);
        assert_eq!(pinned.evidence.decision_id, "vdt_decision_req-1");
        assert_eq!(pinned_target_indices(&targets, &pinned), vec![1]);
    }

    #[test]
    fn select_provider_pool_excludes_missing_credential_region_zdr_and_capabilities() {
        let targets = vec![
            ProviderTarget {
                id: "no-cred".into(),
                provider: "openai".into(),
                model: "gpt-4".into(),
                api_key: "".into(),
                pricing: Some(make_pricing(0.1, 0.1)),
                region: Some("eu".into()),
                ..Default::default()
            },
            ProviderTarget {
                id: "wrong-region".into(),
                provider: "openai".into(),
                model: "gpt-4".into(),
                api_key: "sk".into(),
                pricing: Some(make_pricing(0.1, 0.1)),
                region: Some("us".into()),
                ..Default::default()
            },
            ProviderTarget {
                id: "no-zdr".into(),
                provider: "openai".into(),
                model: "gpt-4".into(),
                api_key: "sk".into(),
                pricing: Some(make_pricing(0.1, 0.1)),
                region: Some("eu".into()),
                zdr: false,
                ..Default::default()
            },
            ProviderTarget {
                id: "no-tools".into(),
                provider: "openai".into(),
                model: "gpt-4".into(),
                api_key: "sk".into(),
                pricing: Some(make_pricing(0.1, 0.1)),
                region: Some("eu".into()),
                zdr: true,
                models: vec![super::super::providers::ProviderModelEntry {
                    model_id: "gpt-4".into(),
                    enabled: true,
                    supported_features: vec!["vision".into()],
                    ..Default::default()
                }],
                ..Default::default()
            },
        ];
        let routing = AutoRoutingConfig::default();
        let metrics = ProviderMetrics::new(60, 1);
        let constraints = ProviderPoolConstraints {
            publication_region: Some("eu".into()),
            require_zdr: true,
            required_capabilities: vec!["tools".into()],
            ..Default::default()
        };
        let err = select_provider_pool(&targets, &routing, &metrics, &constraints, "req-2")
            .expect_err("no eligible");
        assert!(!err.evidence.pinned);
        assert!(!err.evidence.alternate_provider_fallback);
        assert!(err
            .evidence
            .candidates
            .iter()
            .any(|c| c.exclusion_reason == Some("credential_unavailable")));
        assert!(err
            .evidence
            .candidates
            .iter()
            .any(|c| c.exclusion_reason == Some("region_privacy_constraint")));
        assert!(err
            .evidence
            .candidates
            .iter()
            .any(|c| c.exclusion_reason == Some("capability_unsatisfied")));
    }

    #[test]
    fn select_provider_pool_tie_break_is_deterministic_by_id() {
        let targets = vec![
            ProviderTarget {
                id: "b-target".into(),
                api_key: "sk".into(),
                pricing: Some(make_pricing(1.0, 1.0)),
                ..Default::default()
            },
            ProviderTarget {
                id: "a-target".into(),
                api_key: "sk".into(),
                pricing: Some(make_pricing(1.0, 1.0)),
                ..Default::default()
            },
        ];
        let routing = AutoRoutingConfig::default();
        let metrics = ProviderMetrics::new(60, 1);
        let first = select_provider_pool(
            &targets,
            &routing,
            &metrics,
            &ProviderPoolConstraints::default(),
            "tie-1",
        )
        .unwrap();
        let second = select_provider_pool(
            &targets,
            &routing,
            &metrics,
            &ProviderPoolConstraints::default(),
            "tie-2",
        )
        .unwrap();
        assert_eq!(first.target.id, "a-target");
        assert_eq!(second.target.id, "a-target");
    }
}
