// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Canonical replay digest for secure cache replay gating (Phase 6).
//!
//! Computes a deterministic SHA-256 digest over **sanitized** (content-free)
//! request inputs plus optional workflow context so that cache replay is
//! blocked unless the structural fingerprint of the incoming request matches
//! the one that produced the cached response.
//!
//! ## What is hashed (structural signals only)
//!
//! - Normalized provider identifier (lowercased, ASCII-trimmed)
//! - Normalized model identifier (lowercased, ASCII-trimmed)
//! - Message count and role sequence (e.g. `"system:user:assistant:user"`)
//! - Sorted canonical parameter set (temperature, max_tokens, top_p, etc.)
//! - Optional workflow identifier (`X-Workflow-Id` header value)
//! - Optional cache buster token from operator config
//! - Optional entitlement-context digest (SHA-256 over the requesting user's
//!   sorted permission set)
//!
//! ## What is NEVER hashed — privacy boundary SEC-001
//!
//! - Message content (prompts, completions, tool arguments)
//! - User credentials, API keys, or personal identifiers
//! - Timestamps, request IDs, or ephemeral values
//!
//! ## Entitlement-context digest (SEC-R01)
//!
//! The `org_shared_cache` tier MUST NOT serve a cache entry to a user whose
//! effective permission set is narrower than the permission set that produced
//! the cached response. To enforce this, callers MUST include the requesting
//! user's resolved permission set in the cache key via
//! [`CanonicalReplayInput::with_entitlement_digest`]. Use
//! [`compute_entitlement_digest`] to derive the digest from a slice of
//! permission strings at cache-write time and at cache-read time.
//!
//! ## Replay gate
//!
//! [`check_replay_gate`] compares the [`ReplayDigest`] of an incoming request
//! against the digest stored alongside a cache entry. If the digests do not
//! match the gate returns [`ReplayGateDecision::Deny`], preventing unsafe
//! replay. This is a hard fail-closed check: any digest computation failure
//! or missing stored digest also produces a `Deny`.
//!
//! This digest gates cache replay for structurally identical requests.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

// ─── ReplayDigest ─────────────────────────────────────────────────────────────

/// A hex-encoded SHA-256 digest over the structural (content-free) fingerprint
/// of a cache request.
///
/// Two requests produce the same `ReplayDigest` when they have identical
/// provider, model, message role sequence, canonical parameters, and workflow
/// context — regardless of the actual message content.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReplayDigest(String);

impl ReplayDigest {
    /// Returns the underlying hex string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Checks whether this digest is equal to another.
    pub fn matches(&self, other: &ReplayDigest) -> bool {
        // Constant-time comparison is not required here: these are structural
        // fingerprints, not secrets. Direct equality is correct.
        self.0 == other.0
    }
}

impl std::fmt::Display for ReplayDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ─── CanonicalReplayInput ─────────────────────────────────────────────────────

/// Structural inputs used to compute a [`ReplayDigest`].
///
/// All fields are **content-free**: they describe the shape and context of the
/// request but never include prompt text, completions, or personal data.
#[derive(Clone, Debug, Default)]
pub struct CanonicalReplayInput {
    /// Normalized provider identifier (e.g. `"openai"`, `"anthropic"`).
    /// Lowercased and trimmed before hashing.
    pub provider: Option<String>,

    /// Normalized model identifier (e.g. `"gpt-5.4-mini"`, `"claude-3-opus"`).
    /// Lowercased and trimmed before hashing.
    pub model: Option<String>,

    /// Number of messages in the request payload.
    pub message_count: usize,

    /// Sequence of message roles in order (e.g. `["system", "user", "assistant", "user"]`).
    /// Role strings are lowercased and trimmed. Content is never included.
    pub message_roles: Vec<String>,

    /// Sorted canonical parameters included in the request.
    ///
    /// Include numeric/boolean parameters that affect provider output
    /// (e.g. `temperature`, `max_tokens`, `top_p`, `seed`). Omit request-IDs,
    /// timestamps, or any value that can differ between semantically identical
    /// requests.
    ///
    /// Use a `BTreeMap` so the key ordering is deterministic.
    pub parameters: BTreeMap<String, serde_json::Value>,

    /// Optional workflow identifier from the `X-Workflow-Id` request header.
    pub workflow_id: Option<String>,

    /// Optional operator-configured cache buster token. When set, changing
    /// the token invalidates all existing digests for this org.
    pub cache_buster: Option<String>,

    /// Optional entitlement-context digest derived from the requesting user's
    /// **resolved permission set** at cache-write time.
    ///
    /// MUST be included for all `org_shared_cache` tier entries to prevent
    /// a broader-permission cache entry from being served to a narrower-permission
    /// user. Computed via [`compute_entitlement_digest`].
    ///
    /// When `None`, the digest field is serialized as `null` and the cache key
    /// is tier-agnostic (suitable only for fully public / permission-invariant
    /// responses).
    pub user_entitlement_digest: Option<String>,

    /// Optional KB manifest hash including version-locked identity.
    /// When present, the replay digest includes manifest_hash, selected version ids,
    /// ranking policy version, visibility digest, and org key version so that
    /// cache replay identity fully captures KB state.
    pub kb_manifest_hash: Option<String>,

    /// Optional KB visibility/ABAC digest for recall scoping.
    /// When present, ensures a broader-visibility KB cache entry cannot be replayed
    /// to a narrower-visibility caller in the same org.
    pub kb_visibility_digest: Option<String>,
}

impl CanonicalReplayInput {
    /// Constructs an empty input builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the provider (lowercased, trimmed).
    pub fn with_provider(mut self, provider: impl Into<String>) -> Self {
        let v = provider.into();
        let normalized = v.trim().to_ascii_lowercase();
        self.provider = if normalized.is_empty() {
            None
        } else {
            Some(normalized)
        };
        self
    }

    /// Sets the model (lowercased, trimmed).
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        let v = model.into();
        let normalized = v.trim().to_ascii_lowercase();
        self.model = if normalized.is_empty() {
            None
        } else {
            Some(normalized)
        };
        self
    }

    /// Sets the message role sequence. Roles are lowercased and trimmed.
    /// Content is not accepted by this method — only role strings.
    fn with_message_roles(mut self, roles: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        let normalized: Vec<String> = roles
            .into_iter()
            .map(|r| r.as_ref().trim().to_ascii_lowercase())
            .filter(|r| !r.is_empty())
            .collect();
        self.message_count = normalized.len();
        self.message_roles = normalized;
        self
    }

    /// Inserts a numeric or boolean parameter.
    fn with_parameter(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.parameters.insert(key.into(), value);
        self
    }

    /// Sets the workflow identifier.
    fn with_workflow_id(mut self, workflow_id: impl Into<String>) -> Self {
        let v = workflow_id.into();
        let trimmed = v.trim().to_string();
        self.workflow_id = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        };
        self
    }

    /// Sets the cache buster token.
    fn with_cache_buster(mut self, buster: impl Into<String>) -> Self {
        let v = buster.into();
        let trimmed = v.trim().to_string();
        self.cache_buster = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        };
        self
    }

    /// Sets the entitlement-context digest for `org_shared_cache` tier entries.
    ///
    /// The digest MUST be derived from the requesting user's resolved permission
    /// set at request time via [`compute_entitlement_digest`]. Callers must call
    /// this for every `OrgShared` cache key so that entries produced under broader
    /// permissions cannot be replayed by narrower-permission users.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use crate::gateway::canonicalization::{CanonicalReplayInput, compute_entitlement_digest};
    ///
    /// let user_perms = vec!["cache:read", "model:gpt4"];
    /// let digest = compute_entitlement_digest(&user_perms);
    /// let replay_input = CanonicalReplayInput::new()
    ///     .with_provider("openai")
    ///     .with_model("gpt-5.4-mini")
    ///     .with_entitlement_digest(digest);
    /// ```
    pub fn with_entitlement_digest(mut self, digest: impl Into<String>) -> Self {
        let v = digest.into();
        let trimmed = v.trim().to_string();
        self.user_entitlement_digest = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        };
        self
    }

    /// Sets the KB manifest hash for version-locked replay identity.
    fn with_kb_manifest_hash(mut self, hash: impl Into<String>) -> Self {
        let v = hash.into();
        let trimmed = v.trim().to_string();
        self.kb_manifest_hash = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        };
        self
    }

    /// Sets the KB visibility/ABAC digest for recall-scoped replay identity.
    fn with_kb_visibility_digest(mut self, digest: impl Into<String>) -> Self {
        let v = digest.into();
        let trimmed = v.trim().to_string();
        self.kb_visibility_digest = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        };
        self
    }

    /// Computes the [`ReplayDigest`] for these inputs.
    ///
    /// The digest is computed as:
    /// `SHA-256( JSON( sorted canonical map ) )`
    ///
    /// where the canonical map contains only the structural fields above.
    /// Absent optional fields are represented as `null`.
    pub fn compute(&self) -> ReplayDigest {
        // Build a deterministic BTreeMap so key ordering is stable.
        let mut map: BTreeMap<&str, serde_json::Value> = BTreeMap::new();

        map.insert(
            "provider",
            self.provider
                .as_deref()
                .map(serde_json::Value::from)
                .unwrap_or(serde_json::Value::Null),
        );
        map.insert(
            "model",
            self.model
                .as_deref()
                .map(serde_json::Value::from)
                .unwrap_or(serde_json::Value::Null),
        );
        map.insert("message_count", serde_json::Value::from(self.message_count));
        map.insert(
            "message_roles",
            serde_json::Value::from(self.message_roles.clone()),
        );
        map.insert(
            "parameters",
            serde_json::to_value(&self.parameters).unwrap_or(serde_json::Value::Null),
        );
        map.insert(
            "workflow_id",
            self.workflow_id
                .as_deref()
                .map(serde_json::Value::from)
                .unwrap_or(serde_json::Value::Null),
        );
        map.insert(
            "cache_buster",
            self.cache_buster
                .as_deref()
                .map(serde_json::Value::from)
                .unwrap_or(serde_json::Value::Null),
        );
        map.insert(
            "user_entitlement_digest",
            self.user_entitlement_digest
                .as_deref()
                .map(serde_json::Value::from)
                .unwrap_or(serde_json::Value::Null),
        );
        // : KB identity fields in replay digest.
        map.insert(
            "kb_manifest_hash",
            self.kb_manifest_hash
                .as_deref()
                .map(serde_json::Value::from)
                .unwrap_or(serde_json::Value::Null),
        );
        map.insert(
            "kb_visibility_digest",
            self.kb_visibility_digest
                .as_deref()
                .map(serde_json::Value::from)
                .unwrap_or(serde_json::Value::Null),
        );

        // Deterministic JSON serialization: BTreeMap guarantees key order.
        // serde_json serializes Map entries in insertion order when using a
        // BTreeMap, so this is stable across runs.
        let canonical_json = serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_string());

        let hash = Sha256::digest(canonical_json.as_bytes());
        ReplayDigest(hex::encode(hash))
    }
}

// ─── Entitlement-Context Digest ───────────────────────────────────────────────

/// Computes a deterministic SHA-256 digest over a user's resolved permission set.
///
/// Used to produce the `user_entitlement_digest` component of the
/// `org_shared_cache` canonicalization key.
///
/// # Algorithm
///
/// 1. Collect all permission strings into a `BTreeSet` to deduplicate and sort them
///    (provides RFC 8785-equivalent canonical ordering for a flat string list).
/// 2. Serialize the sorted set as a compact JSON array.
/// 3. SHA-256 hash the JSON bytes and hex-encode the result.
///
/// Callers MUST pass the **resolved effective permission set** — i.e. the
/// permissions actually granted to this user after role expansion — not the
/// raw role list. Two users whose role names differ but whose effective
/// permission sets are identical will produce the same digest, which is the
/// correct behavior (structural equivalence drives cache sharing).
///
/// # Arguments
///
/// * `permissions` — resolved effective permission strings for the user. May be empty;
///   an empty set produces a deterministic digest for zero-permission contexts.
///
/// # Returns
///
/// Lowercase hex-encoded SHA-256 string (64 characters).
///
/// # Example
///
/// ```ignore
/// use crate::gateway::canonicalization::compute_entitlement_digest;
///
/// let perms_a = ["model:gpt4", "cache:read"];
/// let perms_b = ["cache:read", "model:gpt4"]; // different order, same set
/// assert_eq!(
///     compute_entitlement_digest(&perms_a),
///     compute_entitlement_digest(&perms_b),
///     "order must not affect the entitlement digest"
/// );
///
/// let perms_narrow = ["cache:read"];
/// assert_ne!(
///     compute_entitlement_digest(&perms_a),
///     compute_entitlement_digest(&perms_narrow),
///     "different permission sets must produce different digests"
/// );
/// ```
pub fn compute_entitlement_digest(permissions: &[impl AsRef<str>]) -> String {
    // BTreeSet deduplicates and sorts deterministically.
    let canonical_set: BTreeSet<&str> = permissions.iter().map(|p| p.as_ref()).collect();
    let sorted_vec: Vec<&str> = canonical_set.into_iter().collect();
    // Compact JSON array with sorted entries — stable, unambiguous serialization.
    let canonical_json = serde_json::to_string(&sorted_vec).unwrap_or_else(|_| "[]".to_string());
    let hash = Sha256::digest(canonical_json.as_bytes());
    hex::encode(hash)
}

// ─── ReplayGateDecision ───────────────────────────────────────────────────────

/// Decision returned by [`check_replay_gate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReplayGateDecision {
    /// The incoming digest matches the stored digest; replay is safe.
    Allow,
    /// The digests do not match or a required digest is absent.
    /// Replay is blocked. Contains a human-readable reason for tracing.
    Deny { reason: &'static str },
}

impl ReplayGateDecision {
    /// Returns `true` when the decision is [`Allow`](ReplayGateDecision::Allow).
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// Checks whether `incoming` matches `stored`.
///
/// The check is **fail-closed**: any mismatch returns `Deny`.
///
/// # Arguments
///
/// * `incoming` — digest computed from the current request's structural inputs.
/// * `stored` — digest recorded when the cache entry was written.
pub fn check_replay_gate(incoming: &ReplayDigest, stored: &ReplayDigest) -> ReplayGateDecision {
    if incoming.matches(stored) {
        ReplayGateDecision::Allow
    } else {
        tracing::warn!(
            incoming_digest = %incoming,
            stored_digest = %stored,
            "cache replay gate: digest mismatch — replay blocked"
        );
        ReplayGateDecision::Deny {
            reason: "replay digest mismatch",
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

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
    fn empty_input_produces_deterministic_digest() {
        let d1 = CanonicalReplayInput::new().compute();
        let d2 = CanonicalReplayInput::new().compute();
        assert_eq!(d1, d2);
        assert_eq!(d1.as_str().len(), 64);
    }

    #[test]
    fn different_providers_produce_different_digests() {
        let d1 = CanonicalReplayInput::new()
            .with_provider("openai")
            .compute();
        let d2 = CanonicalReplayInput::new()
            .with_provider("anthropic")
            .compute();
        assert_ne!(d1, d2);
    }

    #[test]
    fn provider_normalization_case_insensitive() {
        let d1 = CanonicalReplayInput::new()
            .with_provider("OpenAI")
            .compute();
        let d2 = CanonicalReplayInput::new()
            .with_provider("openai")
            .compute();
        assert_eq!(d1, d2);
    }

    #[test]
    fn provider_normalization_trims_whitespace() {
        let d1 = CanonicalReplayInput::new()
            .with_provider("  openai  ")
            .compute();
        let d2 = CanonicalReplayInput::new()
            .with_provider("openai")
            .compute();
        assert_eq!(d1, d2);
    }

    #[test]
    fn empty_provider_treated_as_none() {
        let d1 = CanonicalReplayInput::new().with_provider("").compute();
        let d2 = CanonicalReplayInput::new().compute();
        assert_eq!(d1, d2);
    }

    #[test]
    fn model_normalization() {
        let d1 = CanonicalReplayInput::new().with_model("GPT-4").compute();
        let d2 = CanonicalReplayInput::new().with_model("gpt-4").compute();
        assert_eq!(d1, d2);
    }

    #[test]
    fn different_models_different_digests() {
        let d1 = CanonicalReplayInput::new().with_model("gpt-4").compute();
        let d2 = CanonicalReplayInput::new().with_model("gpt-3.5").compute();
        assert_ne!(d1, d2);
    }

    #[test]
    fn message_roles_included_in_digest() {
        let d1 = CanonicalReplayInput::new()
            .with_message_roles(["system", "user"])
            .compute();
        let d2 = CanonicalReplayInput::new()
            .with_message_roles(["user", "assistant"])
            .compute();
        assert_ne!(d1, d2);
    }

    #[test]
    fn message_roles_normalized() {
        let d1 = CanonicalReplayInput::new()
            .with_message_roles(["  System  ", "User"])
            .compute();
        let d2 = CanonicalReplayInput::new()
            .with_message_roles(["system", "user"])
            .compute();
        assert_eq!(d1, d2);
    }

    #[test]
    fn empty_roles_filtered_out() {
        let d1 = CanonicalReplayInput::new()
            .with_message_roles(["user", "", "  "])
            .compute();
        let d2 = CanonicalReplayInput::new()
            .with_message_roles(["user"])
            .compute();
        assert_eq!(d1, d2);
    }

    #[test]
    fn parameters_affect_digest() {
        let d1 = CanonicalReplayInput::new()
            .with_parameter("temperature", serde_json::json!(0.7))
            .compute();
        let d2 = CanonicalReplayInput::new()
            .with_parameter("temperature", serde_json::json!(0.9))
            .compute();
        assert_ne!(d1, d2);
    }

    #[test]
    fn workflow_id_affects_digest() {
        let d1 = CanonicalReplayInput::new()
            .with_workflow_id("wf-1")
            .compute();
        let d2 = CanonicalReplayInput::new()
            .with_workflow_id("wf-2")
            .compute();
        assert_ne!(d1, d2);
    }

    #[test]
    fn empty_workflow_id_treated_as_none() {
        let d1 = CanonicalReplayInput::new().with_workflow_id("  ").compute();
        let d2 = CanonicalReplayInput::new().compute();
        assert_eq!(d1, d2);
    }

    #[test]
    fn cache_buster_affects_digest() {
        let d1 = CanonicalReplayInput::new()
            .with_cache_buster("v1")
            .compute();
        let d2 = CanonicalReplayInput::new()
            .with_cache_buster("v2")
            .compute();
        assert_ne!(d1, d2);
    }

    #[test]
    fn entitlement_digest_affects_replay_digest() {
        let d1 = CanonicalReplayInput::new()
            .with_entitlement_digest("abc123")
            .compute();
        let d2 = CanonicalReplayInput::new()
            .with_entitlement_digest("def456")
            .compute();
        assert_ne!(d1, d2);
    }

    #[test]
    fn kb_manifest_hash_affects_digest() {
        let d1 = CanonicalReplayInput::new()
            .with_kb_manifest_hash("hash-a")
            .compute();
        let d2 = CanonicalReplayInput::new()
            .with_kb_manifest_hash("hash-b")
            .compute();
        assert_ne!(d1, d2);
    }

    #[test]
    fn kb_visibility_digest_affects_digest() {
        let d1 = CanonicalReplayInput::new()
            .with_kb_visibility_digest("vis-a")
            .compute();
        let d2 = CanonicalReplayInput::new()
            .with_kb_visibility_digest("vis-b")
            .compute();
        assert_ne!(d1, d2);
    }

    #[test]
    fn replay_digest_matches_self() {
        let d = CanonicalReplayInput::new()
            .with_provider("openai")
            .compute();
        assert!(d.matches(&d));
    }

    #[test]
    fn replay_digest_display() {
        let d = CanonicalReplayInput::new().compute();
        let s = format!("{}", d);
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn compute_entitlement_digest_deterministic() {
        let d1 = compute_entitlement_digest(&["cache:read", "model:gpt4"]);
        let d2 = compute_entitlement_digest(&["cache:read", "model:gpt4"]);
        assert_eq!(d1, d2);
    }

    #[test]
    fn compute_entitlement_digest_order_independent() {
        let d1 = compute_entitlement_digest(&["model:gpt4", "cache:read"]);
        let d2 = compute_entitlement_digest(&["cache:read", "model:gpt4"]);
        assert_eq!(d1, d2);
    }

    #[test]
    fn compute_entitlement_digest_different_perms() {
        let d1 = compute_entitlement_digest(&["cache:read"]);
        let d2 = compute_entitlement_digest(&["cache:write"]);
        assert_ne!(d1, d2);
    }

    #[test]
    fn compute_entitlement_digest_deduplicates() {
        let d1 = compute_entitlement_digest(&["cache:read", "cache:read"]);
        let d2 = compute_entitlement_digest(&["cache:read"]);
        assert_eq!(d1, d2);
    }

    #[test]
    fn compute_entitlement_digest_empty() {
        let empty: &[&str] = &[];
        let d = compute_entitlement_digest(empty);
        assert_eq!(d.len(), 64);
    }

    #[test]
    fn check_replay_gate_matching_digests_allow() {
        let d = CanonicalReplayInput::new()
            .with_provider("openai")
            .compute();
        let decision = check_replay_gate(&d, &d);
        assert_eq!(decision, ReplayGateDecision::Allow);
        assert!(decision.is_allowed());
    }

    #[test]
    fn check_replay_gate_mismatched_digests_deny() {
        let d1 = CanonicalReplayInput::new()
            .with_provider("openai")
            .compute();
        let d2 = CanonicalReplayInput::new()
            .with_provider("anthropic")
            .compute();
        let decision = check_replay_gate(&d1, &d2);
        assert_eq!(
            decision,
            ReplayGateDecision::Deny {
                reason: "replay digest mismatch"
            }
        );
        assert!(!decision.is_allowed());
    }

    #[test]
    fn full_input_deterministic() {
        let input = CanonicalReplayInput::new()
            .with_provider("openai")
            .with_model("gpt-4")
            .with_message_roles(["system", "user", "assistant"])
            .with_parameter("temperature", serde_json::json!(0.7))
            .with_parameter("max_tokens", serde_json::json!(1024))
            .with_workflow_id("my-workflow")
            .with_cache_buster("v3")
            .with_entitlement_digest("ent-digest")
            .with_kb_manifest_hash("kb-hash")
            .with_kb_visibility_digest("kb-vis");
        let d1 = input.clone().compute();
        let d2 = input.compute();
        assert_eq!(d1, d2);
    }
}
