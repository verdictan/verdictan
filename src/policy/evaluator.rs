// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::collections::HashMap;

use axum::http::HeaderMap;
use serde_json::Value;

use crate::gateway::declarative_config::MatchListOrWildcard;
use crate::gateway::enforcement::{PolicyResult, Verdict};
use crate::gateway::identity::PolicyIdentityContext;

/// Inputs consumed by [`evaluate_rbac`].
///
/// [`HeaderMap`] alone yields no verified identity (spoofable headers are never
/// treated as role claims). Pass [`RbacIdentityBinding`] when a verified
/// [`PolicyIdentityContext`] is available.
pub trait RbacEvaluationInput {
    fn headers(&self) -> &HeaderMap;
    fn policy_identity(&self) -> Option<&PolicyIdentityContext>;
}

impl RbacEvaluationInput for HeaderMap {
    fn headers(&self) -> &HeaderMap {
        self
    }

    fn policy_identity(&self) -> Option<&PolicyIdentityContext> {
        None
    }
}

/// Headers plus an optional verified policy identity.
#[derive(Debug, Clone, Copy)]
pub struct RbacIdentityBinding<'a> {
    pub headers: &'a HeaderMap,
    pub identity: Option<&'a PolicyIdentityContext>,
}

impl RbacEvaluationInput for RbacIdentityBinding<'_> {
    fn headers(&self) -> &HeaderMap {
        self.headers
    }

    fn policy_identity(&self) -> Option<&PolicyIdentityContext> {
        self.identity
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ToolPatternPolicy {
    allowed: Vec<String>,
    denied: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolAccessScope {
    Global,
    Role,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolAccessReason {
    Allowed(ToolAccessScope),
    ExplicitDeny(ToolAccessScope),
    NotAllowed(ToolAccessScope),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolAccessDecision {
    pub verdict: Verdict,
    pub reason: ToolAccessReason,
}

impl ToolAccessDecision {
    fn allowed(scope: ToolAccessScope) -> Self {
        Self {
            verdict: Verdict::Allow,
            reason: ToolAccessReason::Allowed(scope),
        }
    }

    fn explicit_deny(scope: ToolAccessScope) -> Self {
        Self {
            verdict: Verdict::Block,
            reason: ToolAccessReason::ExplicitDeny(scope),
        }
    }

    fn not_allowed(scope: ToolAccessScope) -> Self {
        Self {
            verdict: Verdict::Block,
            reason: ToolAccessReason::NotAllowed(scope),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum RoleFallbackMode {
    #[default]
    UseGlobal,
    DenyWhenRolePoliciesConfigured,
}

#[derive(Debug, Clone, Default)]
pub struct ToolAccessEvaluator {
    global: ToolPatternPolicy,
    role_policies: HashMap<String, ToolPatternPolicy>,
    role_fallback_mode: RoleFallbackMode,
}

impl ToolAccessEvaluator {
    pub fn from_match_list(allowed_tools: &MatchListOrWildcard) -> Self {
        let allowed = match allowed_tools {
            MatchListOrWildcard::Wildcard => vec!["*".to_string()],
            MatchListOrWildcard::Explicit(values) => values.clone(),
        };
        Self {
            global: ToolPatternPolicy {
                allowed,
                denied: Vec::new(),
            },
            role_policies: HashMap::new(),
            role_fallback_mode: RoleFallbackMode::UseGlobal,
        }
    }

    pub fn from_rbac_config(config: Option<&serde_json::Map<String, Value>>) -> Self {
        Self {
            global: ToolPatternPolicy::default(),
            role_policies: role_policies_from_value(
                config.and_then(|value| value.get("roles")),
                "allowed_tools",
                "denied_tools",
            ),
            role_fallback_mode: RoleFallbackMode::DenyWhenRolePoliciesConfigured,
        }
    }

    pub fn from_agent_firewall_config(config: Option<&serde_json::Map<String, Value>>) -> Self {
        let allowed = config
            .and_then(|value| value.get("allowed_tools"))
            .map(string_array)
            .unwrap_or_else(|| vec!["*".to_string()]);
        let denied = config
            .and_then(|value| value.get("blocked_tools"))
            .map(string_array)
            .unwrap_or_default();

        Self {
            global: ToolPatternPolicy { allowed, denied },
            role_policies: role_policies_from_value(
                config
                    .and_then(|value| value.get("tools"))
                    .and_then(|value| value.get("roles")),
                "allowed",
                "denied",
            ),
            role_fallback_mode: RoleFallbackMode::UseGlobal,
        }
    }

    pub fn evaluate(&self, tool_name: &str, role: Option<&str>) -> ToolAccessDecision {
        if let Some(role_name) = role {
            if let Some(policy) = self.role_policies.get(role_name) {
                if matches_any(&policy.denied, tool_name) {
                    return ToolAccessDecision::explicit_deny(ToolAccessScope::Role);
                }
                if !policy.allowed.is_empty() {
                    if matches_any(&policy.allowed, tool_name) {
                        return ToolAccessDecision::allowed(ToolAccessScope::Role);
                    }
                    return ToolAccessDecision::not_allowed(ToolAccessScope::Role);
                }
                if self.role_fallback_mode == RoleFallbackMode::DenyWhenRolePoliciesConfigured {
                    return ToolAccessDecision::not_allowed(ToolAccessScope::Role);
                }
            } else if !self.role_policies.is_empty()
                && self.role_fallback_mode == RoleFallbackMode::DenyWhenRolePoliciesConfigured
            {
                return ToolAccessDecision::not_allowed(ToolAccessScope::Role);
            }
        }

        if matches_any(&self.global.denied, tool_name) {
            return ToolAccessDecision::explicit_deny(ToolAccessScope::Global);
        }
        if matches_any(&self.global.allowed, tool_name) {
            return ToolAccessDecision::allowed(ToolAccessScope::Global);
        }

        ToolAccessDecision::not_allowed(ToolAccessScope::Global)
    }

    pub fn allows(&self, tool_name: &str, role: Option<&str>) -> bool {
        self.evaluate(tool_name, role).verdict == Verdict::Allow
    }

    pub fn global_allowed_patterns(&self) -> &[String] {
        &self.global.allowed
    }

    pub fn role_allowed_patterns(&self, role: &str) -> &[String] {
        self.role_policies
            .get(role)
            .map(|policy| policy.allowed.as_slice())
            .unwrap_or(&[])
    }
}

pub fn evaluate_rbac(
    config: Option<&Value>,
    request_json: Option<&Value>,
    input: &impl RbacEvaluationInput,
) -> PolicyResult {
    let phase = "input".to_string();
    let headers = input.headers();
    let identity = input.policy_identity();

    let Some(cfg) = config.and_then(|value| value.as_object()) else {
        return PolicyResult {
            policy_kind: "rbac".to_string(),
            phase,
            verdict: Verdict::Block,
            reason_code: "policy.rbac_configuration_required".to_string(),
            details: None,
            redaction_targets: None,
        };
    };

    let roles_tbl = cfg
        .get("roles")
        .and_then(|value| value.as_object())
        .cloned()
        .unwrap_or_default();
    let role_rules_configured = !roles_tbl.is_empty();
    let tool_access = ToolAccessEvaluator::from_rbac_config(Some(cfg));

    // Auth is required unless the policy explicitly opts out.
    let require_auth = cfg
        .get("require_auth")
        .and_then(|value| value.as_bool())
        .unwrap_or(true);

    let deny_if_missing = cfg
        .get("deny_if_missing")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(|value| value.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let verified = identity.is_some();

    let mut missing: Vec<String> = deny_if_missing
        .iter()
        .filter(|name| header_missing_or_empty(headers, name.as_str()))
        .cloned()
        .collect();

    if require_auth && !verified {
        missing.push("verified_policy_identity".to_string());
    }
    missing.sort();
    missing.dedup();

    if !missing.is_empty() {
        return PolicyResult {
            policy_kind: "rbac".to_string(),
            phase,
            verdict: Verdict::Block,
            reason_code: "rbac.missing_identity".to_string(),
            details: Some(serde_json::json!({ "missing_headers": missing })),
            redaction_targets: None,
        };
    }

    // Roles come only from verified claims — never from spoofable headers or
    // config defaults keyed off X-Key-ID / Authorization presentation.
    let verified_roles: Vec<String> = identity
        .map(|ctx| {
            ctx.roles
                .iter()
                .map(|role| role.trim())
                .filter(|role| !role.is_empty())
                .map(|role| role.to_string())
                .collect()
        })
        .unwrap_or_default();

    let primary_role = verified_roles.first().cloned();

    if role_rules_configured && verified_roles.is_empty() {
        return PolicyResult {
            policy_kind: "rbac".to_string(),
            phase,
            verdict: Verdict::Block,
            reason_code: "rbac.missing_role".to_string(),
            details: Some(serde_json::json!({
                "required": "verified_role_claim",
            })),
            redaction_targets: None,
        };
    }

    let mut invalid: Vec<String> = deny_if_missing
        .iter()
        .filter(|name| header_present_but_invalid_identity(headers, name.as_str()))
        .cloned()
        .collect();
    invalid.sort();
    invalid.dedup();

    if !invalid.is_empty() {
        return PolicyResult {
            policy_kind: "rbac".to_string(),
            phase,
            verdict: Verdict::Block,
            reason_code: "rbac.invalid_identity".to_string(),
            details: Some(serde_json::json!({ "invalid_headers": invalid })),
            redaction_targets: None,
        };
    }

    if !verified_roles.is_empty() {
        let tool_names = extract_tool_names(request_json);
        for tool in &tool_names {
            let mut allowed = false;
            let mut deny_role: Option<&str> = None;
            let mut deny_cause: Option<&str> = None;

            for role in &verified_roles {
                let decision = tool_access.evaluate(tool, Some(role.as_str()));
                match decision.reason {
                    ToolAccessReason::ExplicitDeny(_) => {
                        deny_role = Some(role.as_str());
                        deny_cause = Some("denied");
                        break;
                    }
                    ToolAccessReason::Allowed(_) => {
                        allowed = true;
                    }
                    ToolAccessReason::NotAllowed(_) => {}
                }
            }

            if let (Some(role), Some(cause)) = (deny_role, deny_cause) {
                return PolicyResult {
                    policy_kind: "rbac".to_string(),
                    phase,
                    verdict: Verdict::Block,
                    reason_code: "rbac.tool_not_allowed".to_string(),
                    details: Some(serde_json::json!({
                        "role": role,
                        "roles": verified_roles,
                        "tool": tool,
                        "cause": cause,
                    })),
                    redaction_targets: None,
                };
            }

            if !allowed {
                return PolicyResult {
                    policy_kind: "rbac".to_string(),
                    phase,
                    verdict: Verdict::Block,
                    reason_code: "rbac.tool_not_allowed".to_string(),
                    details: Some(serde_json::json!({
                        "role": primary_role,
                        "roles": verified_roles,
                        "tool": tool,
                        "cause": "not_allowed",
                    })),
                    redaction_targets: None,
                };
            }
        }
    }

    if let Some(data_access_tbl) = cfg.get("data_access").and_then(|value| value.as_object()) {
        let requested = extract_requested_sensitivity(request_json).unwrap_or("public");
        let mut saw_role_cfg = false;
        let mut permitted = false;
        let mut limiting_role: Option<&str> = None;
        let mut limiting_max: Option<&str> = None;

        for role in &verified_roles {
            let Some(role_cfg) = data_access_tbl
                .get(role)
                .and_then(|value| value.as_object())
            else {
                continue;
            };
            saw_role_cfg = true;
            let max_sensitivity = role_cfg
                .get("max_sensitivity")
                .and_then(|value| value.as_str())
                .unwrap_or("public");
            if sensitivity_rank(requested) <= sensitivity_rank(max_sensitivity) {
                permitted = true;
                break;
            }
            limiting_role = Some(role.as_str());
            limiting_max = Some(max_sensitivity);
        }

        if saw_role_cfg && !permitted {
            return PolicyResult {
                policy_kind: "rbac".to_string(),
                phase,
                verdict: Verdict::Block,
                reason_code: "rbac.data_access_denied".to_string(),
                details: Some(serde_json::json!({
                    "role": limiting_role,
                    "roles": verified_roles,
                    "requested_sensitivity": requested,
                    "max_sensitivity": limiting_max.unwrap_or("public"),
                })),
                redaction_targets: None,
            };
        }
    }

    if let Some(minimum_necessary) = cfg
        .get("minimum_necessary")
        .and_then(|value| value.as_object())
    {
        let enabled = minimum_necessary
            .get("enabled")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        if enabled {
            let allowed_roles = minimum_necessary
                .get("allowed_phi_roles")
                .and_then(|value| value.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(|value| value.to_string()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            let role_permitted = verified_roles
                .iter()
                .any(|role| allowed_roles.iter().any(|allowed| allowed == role));

            if !verified_roles.is_empty() && !allowed_roles.is_empty() && !role_permitted {
                let text = extract_joined_message_text(request_json);
                if !text.is_empty() {
                    let phi = crate::gateway::detection::hipaa::detect_hipaa_18_like(&text);
                    if !phi.is_empty() {
                        return PolicyResult {
                            policy_kind: "rbac".to_string(),
                            phase,
                            verdict: Verdict::Block,
                            reason_code: "rbac.minimum_necessary".to_string(),
                            details: Some(serde_json::json!({
                                "role": primary_role,
                                "roles": verified_roles,
                                "phi_detections": phi.len(),
                            })),
                            redaction_targets: None,
                        };
                    }
                }
            }
        }
    }

    PolicyResult {
        policy_kind: "rbac".to_string(),
        phase,
        verdict: Verdict::Allow,
        reason_code: "rbac.allowed".to_string(),
        details: primary_role.map(|role| {
            serde_json::json!({
                "role": role,
                "roles": verified_roles,
                "subject": identity.map(|ctx| ctx.subject.as_str()),
                "org_id": identity.map(|ctx| ctx.org_id.as_str()),
                "proof_method": identity.map(|ctx| ctx.proof_method.as_str()),
            })
        }),
        redaction_targets: None,
    }
}

fn role_policies_from_value(
    roles_value: Option<&Value>,
    allowed_key: &str,
    denied_key: &str,
) -> HashMap<String, ToolPatternPolicy> {
    roles_value
        .and_then(|value| value.as_object())
        .map(|roles| {
            roles
                .iter()
                .map(|(role, config)| {
                    let allowed = config
                        .get(allowed_key)
                        .map(string_array)
                        .unwrap_or_default();
                    let denied = config.get(denied_key).map(string_array).unwrap_or_default();
                    (role.clone(), ToolPatternPolicy { allowed, denied })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(|value| value.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn matches_any(patterns: &[String], tool_name: &str) -> bool {
    patterns
        .iter()
        .any(|pattern| glob_match(pattern, tool_name))
}

fn extract_requested_sensitivity(request_json: Option<&Value>) -> Option<&'static str> {
    let value = request_json?;
    value
        .get("verdictan")
        .and_then(|inner| inner.get("data_sensitivity"))
        .and_then(|inner| inner.as_str())
        .and_then(normalize_sensitivity)
}

fn normalize_sensitivity(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "public" => Some("public"),
        "internal" => Some("internal"),
        "confidential" => Some("confidential"),
        "restricted" => Some("restricted"),
        _ => None,
    }
}

pub fn sensitivity_rank(value: &str) -> u8 {
    match value.trim().to_ascii_lowercase().as_str() {
        "public" => 0,
        "internal" => 1,
        "confidential" => 2,
        "restricted" => 3,
        _ => 0,
    }
}

fn extract_joined_message_text(request_json: Option<&Value>) -> String {
    let Some(value) = request_json else {
        return String::new();
    };
    let Some(messages) = value.get("messages").and_then(|inner| inner.as_array()) else {
        return String::new();
    };
    messages
        .iter()
        .filter_map(|message| message.get("content").and_then(|content| content.as_str()))
        .collect::<Vec<_>>()
        .join("\n")
}

fn header_missing_or_empty(headers: &HeaderMap, name: &str) -> bool {
    let Some(value) = headers.get(name) else {
        return true;
    };
    let Ok(text) = value.to_str() else {
        return true;
    };
    text.trim().is_empty()
}

fn header_present_but_invalid_identity(headers: &HeaderMap, name: &str) -> bool {
    let should_validate = matches!(name, "X-User-ID" | "X-Org-ID" | "X-User-Role");
    if !should_validate {
        return false;
    }

    let Some(value) = headers.get(name) else {
        return false;
    };
    let Ok(text) = value.to_str() else {
        return true;
    };
    let text = text.trim();
    if text.is_empty() {
        return false;
    }

    !text.chars().all(|character| {
        character.is_ascii_alphanumeric()
            || character == '-'
            || character == '_'
            || character == '.'
    })
}

fn extract_tool_names(request_json: Option<&Value>) -> Vec<String> {
    let Some(value) = request_json else {
        return Vec::new();
    };
    let Some(tools) = value.get("tools").and_then(|inner| inner.as_array()) else {
        return Vec::new();
    };

    tools
        .iter()
        .filter_map(|tool| {
            let name = tool
                .get("function")
                .and_then(|function| function.get("name"))
                .and_then(|value| value.as_str())
                .or_else(|| tool.get("name").and_then(|value| value.as_str()))?;
            let name = name.trim();
            if name.is_empty() {
                None
            } else {
                Some(name.to_string())
            }
        })
        .collect()
}

pub fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == text;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    let mut remainder = text;

    if let Some(first) = parts.first() {
        if !pattern.starts_with('*') {
            if !remainder.starts_with(first) {
                return false;
            }
            remainder = &remainder[first.len()..];
        }
    }

    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if index == 0 && !pattern.starts_with('*') {
            continue;
        }
        if let Some(found_at) = remainder.find(part) {
            remainder = &remainder[found_at + part.len()..];
        } else {
            return false;
        }
    }

    if !pattern.ends_with('*') {
        if let Some(last) = parts.last() {
            return text.ends_with(last);
        }
    }

    true
}

pub fn identity_proof_method_for_header_auth() -> &'static str {
    crate::gateway::identity::IdentityProofMethod::HeaderSoft.as_str()
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

    fn header_map(entries: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for &(name, value) in entries {
            let header_name: axum::http::header::HeaderName = name.parse().unwrap();
            headers.insert(header_name, value.parse().unwrap());
        }
        headers
    }

    #[test]
    fn glob_match_supports_exact_prefix_suffix_and_contains_patterns() {
        assert!(glob_match("cache:invalidate", "cache:invalidate"));
        assert!(glob_match("cache:*", "cache:invalidate"));
        assert!(glob_match("*:invalidate", "cache:invalidate"));
        assert!(glob_match("cache*ate", "cache:invalidate"));
        assert!(!glob_match("events:*", "cache:invalidate"));
    }

    #[test]
    fn tool_access_evaluator_from_match_list_wildcard_allows_any_tool() {
        let evaluator = ToolAccessEvaluator::from_match_list(&MatchListOrWildcard::Wildcard);
        let decision = evaluator.evaluate("mcp.read", None);
        assert_eq!(decision.verdict, Verdict::Allow);
        assert_eq!(
            decision.reason,
            ToolAccessReason::Allowed(ToolAccessScope::Global)
        );
    }

    #[test]
    fn tool_access_evaluator_role_explicit_deny_beats_allow() {
        let config = json!({
            "roles": {
                "analyst": {
                    "allowed_tools": ["search*"],
                    "denied_tools": ["search.delete"]
                }
            }
        });
        let evaluator = ToolAccessEvaluator::from_rbac_config(config.as_object());
        let decision = evaluator.evaluate("search.delete", Some("analyst"));
        assert_eq!(decision.verdict, Verdict::Block);
        assert_eq!(
            decision.reason,
            ToolAccessReason::ExplicitDeny(ToolAccessScope::Role)
        );
    }

    #[test]
    fn tool_access_evaluator_unknown_role_is_denied_when_role_policies_exist() {
        let config = json!({
            "roles": {
                "admin": {
                    "allowed_tools": ["*"]
                }
            }
        });
        let evaluator = ToolAccessEvaluator::from_rbac_config(config.as_object());
        let decision = evaluator.evaluate("cache:read", Some("viewer"));
        assert_eq!(decision.verdict, Verdict::Block);
        assert_eq!(
            decision.reason,
            ToolAccessReason::NotAllowed(ToolAccessScope::Role)
        );
    }

    #[test]
    fn tool_access_evaluator_agent_firewall_falls_back_to_global_policy() {
        let config = json!({
            "allowed_tools": ["mcp*"],
            "blocked_tools": ["mcp.secret"],
            "tools": {
                "roles": {
                    "admin": {
                        "allowed": ["mcp.admin*"],
                        "denied": ["mcp.admin.destroy"]
                    }
                }
            }
        });
        let evaluator = ToolAccessEvaluator::from_agent_firewall_config(config.as_object());
        assert!(evaluator.allows("mcp.search", Some("viewer")));
        assert!(!evaluator.allows("mcp.secret", Some("viewer")));
    }

    #[test]
    fn header_present_but_invalid_identity_rejects_symbols() {
        let headers = header_map(&[("X-User-ID", "alice@example.com")]);
        assert!(header_present_but_invalid_identity(&headers, "X-User-ID"));

        let headers = header_map(&[("X-User-ID", "alice_123")]);
        assert!(!header_present_but_invalid_identity(&headers, "X-User-ID"));
    }

    #[test]
    fn extract_tool_names_supports_function_and_plain_name_forms() {
        let request = json!({
            "tools": [
                {"function": {"name": "cache:invalidate"}},
                {"name": "events:read"},
                {"name": "   "}
            ]
        });
        assert_eq!(
            extract_tool_names(Some(&request)),
            vec!["cache:invalidate".to_string(), "events:read".to_string()]
        );
    }

    #[test]
    fn evaluate_rbac_rejects_missing_configuration() {
        let result = evaluate_rbac(None, None, &HeaderMap::new());
        assert_eq!(result.verdict, Verdict::Block);
        assert_eq!(result.reason_code, "policy.rbac_configuration_required");
    }

    #[test]
    fn evaluate_rbac_require_auth_defaults_true_without_verified_identity() {
        let config = json!({});
        let result = evaluate_rbac(Some(&config), None, &HeaderMap::new());
        assert_eq!(result.verdict, Verdict::Block);
        assert_eq!(result.reason_code, "rbac.missing_identity");
    }

    #[test]
    fn evaluate_rbac_blocks_missing_deny_if_missing_headers() {
        let config = json!({
            "require_auth": false,
            "deny_if_missing": ["X-User-ID"]
        });
        let result = evaluate_rbac(Some(&config), None, &HeaderMap::new());
        assert_eq!(result.verdict, Verdict::Block);
        assert_eq!(result.reason_code, "rbac.missing_identity");
    }

    #[test]
    fn evaluate_rbac_ignores_spoofed_role_headers() {
        let config = json!({
            "require_auth": false,
            "roles": {
                "analyst": {
                    "allowed_tools": ["*"]
                }
            }
        });
        let headers = header_map(&[("X-User-Role", "analyst")]);
        let result = evaluate_rbac(Some(&config), None, &headers);
        assert_eq!(result.verdict, Verdict::Block);
        assert_eq!(result.reason_code, "rbac.missing_role");
    }

    #[test]
    fn evaluate_rbac_ignores_default_token_role_without_verified_identity() {
        let config = json!({
            "require_auth": false,
            "default_token_role": "automation",
            "roles": {
                "automation": {
                    "allowed_tools": ["cache:*"]
                }
            }
        });
        let headers = header_map(&[("X-Key-ID", "key-123")]);
        let request = json!({
            "tools": [
                {"function": {"name": "cache:invalidate"}}
            ]
        });
        let result = evaluate_rbac(Some(&config), Some(&request), &headers);
        assert_eq!(result.verdict, Verdict::Block);
        assert_eq!(result.reason_code, "rbac.missing_role");
    }

    #[test]
    fn evaluate_rbac_allows_verified_role_for_allowed_tools() {
        let identity = policy_identity_with_roles(&["automation"]);
        let config = json!({
            "roles": {
                "automation": {
                    "allowed_tools": ["cache:*"]
                }
            }
        });
        let headers = HeaderMap::new();
        let request = json!({
            "tools": [
                {"function": {"name": "cache:invalidate"}}
            ]
        });
        let input = RbacIdentityBinding {
            headers: &headers,
            identity: Some(&identity),
        };
        let result = evaluate_rbac(Some(&config), Some(&request), &input);
        assert_eq!(result.verdict, Verdict::Allow);
        assert_eq!(result.reason_code, "rbac.allowed");
        assert_eq!(
            result
                .details
                .as_ref()
                .and_then(|details| details.get("role"))
                .and_then(Value::as_str),
            Some("automation")
        );
    }

    #[test]
    fn evaluate_rbac_blocks_tool_not_allowed_for_verified_role() {
        let identity = policy_identity_with_roles(&["automation"]);
        let config = json!({
            "roles": {
                "automation": {
                    "allowed_tools": ["events:*"]
                }
            }
        });
        let headers = HeaderMap::new();
        let request = json!({
            "tools": [
                {"function": {"name": "cache:invalidate"}}
            ]
        });
        let input = RbacIdentityBinding {
            headers: &headers,
            identity: Some(&identity),
        };
        let result = evaluate_rbac(Some(&config), Some(&request), &input);
        assert_eq!(result.verdict, Verdict::Block);
        assert_eq!(result.reason_code, "rbac.tool_not_allowed");
        assert_eq!(
            result
                .details
                .as_ref()
                .and_then(|details| details.get("cause"))
                .and_then(Value::as_str),
            Some("not_allowed")
        );
    }

    #[test]
    fn evaluate_rbac_blocks_requested_sensitivity_above_verified_role_limit() {
        let identity = policy_identity_with_roles(&["analyst"]);
        let config = json!({
            "roles": {
                "analyst": {
                    "allowed_tools": ["*"]
                }
            },
            "data_access": {
                "analyst": {
                    "max_sensitivity": "internal"
                }
            }
        });
        let headers = HeaderMap::new();
        let request = json!({
            "verdictan": {
                "data_sensitivity": "restricted"
            }
        });
        let input = RbacIdentityBinding {
            headers: &headers,
            identity: Some(&identity),
        };
        let result = evaluate_rbac(Some(&config), Some(&request), &input);
        assert_eq!(result.verdict, Verdict::Block);
        assert_eq!(result.reason_code, "rbac.data_access_denied");
    }

    #[test]
    fn evaluate_rbac_require_auth_false_allows_without_identity_when_no_role_rules() {
        let config = json!({
            "require_auth": false
        });
        let result = evaluate_rbac(Some(&config), None, &HeaderMap::new());
        assert_eq!(result.verdict, Verdict::Allow);
        assert_eq!(result.reason_code, "rbac.allowed");
    }

    #[test]
    fn sensitivity_rank_orders_values_from_public_to_restricted() {
        assert!(sensitivity_rank("public") < sensitivity_rank("internal"));
        assert!(sensitivity_rank("internal") < sensitivity_rank("confidential"));
        assert!(sensitivity_rank("confidential") < sensitivity_rank("restricted"));
        assert_eq!(sensitivity_rank("unknown"), 0);
    }

    fn policy_identity_with_roles(roles: &[&str]) -> PolicyIdentityContext {
        let identity =
            crate::gateway::identity::AuthenticatedRequestIdentity::from_validated_claims(
                crate::gateway::identity::AuthenticatedIdentityClaims {
                    proof_method: crate::gateway::identity::IdentityProofMethod::ApiToken,
                    issuer: "verdictan-api".to_string(),
                    subject: "user-1".to_string(),
                    credential_id: "token-1".to_string(),
                    org_id: "org-1".to_string(),
                    team_ids: vec!["team-1".to_string()],
                    roles: roles.iter().map(|role| (*role).to_string()).collect(),
                    scopes: vec!["gateway:invoke".to_string()],
                    assurance_level: crate::gateway::identity::IdentityAssuranceLevel::Token,
                    expires_at: None,
                },
            )
            .expect("authenticated identity");
        identity.to_policy_identity_context()
    }
}
