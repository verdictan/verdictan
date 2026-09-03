// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Zero Data Retention enforcement for gateway provider traffic.
//!
//! Controls whether request/response bodies are cached, logged in events,
//! or stored upstream — depending on the configured ZDR mode.
//!
//! Strict sanitization strips content-bearing fields (`request_body`,
//! `response_body`, `prompt`, `completion`) while preserving non-content
//! accounting (token counts, costs) and decision evidence (policy version /
//! digest, allow/deny reason, reservation and request IDs).

use serde::{Deserialize, Serialize};

use super::provider_adapters::ProviderAdapter;

/// Zero Data Retention mode — controls upstream `store` flag and caching.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ZdrMode {
    /// Normal operation — caching allowed, store=true (provider default).
    #[default]
    Off,
    /// Set store=false on upstream, skip cache writes.
    Passthrough,
    /// Passthrough + no event body logging (strictest mode).
    Strict,
}

/// Content-bearing event keys removed under [`ZdrMode::Strict`].
const STRICT_STRIPPED_CONTENT_KEYS: &[&str] =
    &["request_body", "response_body", "prompt", "completion"];

/// Enforces ZDR policy on requests and event payloads.
pub struct ZdrEnforcer {
    mode: ZdrMode,
}

impl ZdrEnforcer {
    pub fn new(mode: ZdrMode) -> Self {
        Self { mode }
    }

    /// Returns the current ZDR mode.
    pub fn mode(&self) -> &ZdrMode {
        &self.mode
    }

    /// Whether response caching should be skipped (passthrough or strict).
    fn should_skip_cache(&self) -> bool {
        self.mode != ZdrMode::Off
    }

    /// Whether event bodies should be stripped from trace/audit payloads.
    fn should_strip_event_bodies(&self) -> bool {
        self.mode == ZdrMode::Strict
    }

    /// Apply provider-specific ZDR overrides to the request body.
    /// For OpenAI this sets `store: false`; for Anthropic this is a no-op
    /// (handled via contractual agreement).
    fn apply_to_request(&self, body: &mut serde_json::Value, adapter: &dyn ProviderAdapter) {
        if self.mode != ZdrMode::Off {
            adapter.apply_zdr_overrides(body);
        }
    }

    /// Strip sensitive content fields from an event payload before forwarding
    /// to the control plane.
    ///
    /// In Strict mode, removes request/response bodies and embedded prompt /
    /// completion text. Non-content accounting and decision-evidence fields
    /// (token usage, costs, policy version/digest, decisions, reservation and
    /// request IDs, latency) are left intact.
    fn sanitize_event_payload(&self, payload: &mut serde_json::Value) {
        if self.mode == ZdrMode::Strict {
            if let Some(obj) = payload.as_object_mut() {
                for key in STRICT_STRIPPED_CONTENT_KEYS {
                    obj.remove(*key);
                }
            }
        }
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
    use serde_json::json;

    struct MockAdapter;
    impl ProviderAdapter for MockAdapter {
        fn provider_id(&self) -> &str {
            "mock"
        }
        fn supported_formats(&self) -> &[super::super::provider_adapters::ApiFormat] {
            &[]
        }
        fn build_upstream_request(
            &self,
            _body: &serde_json::Value,
            _credential: &super::super::provider_execution::ProviderCredential,
            _options: &super::super::provider_execution::RequestOptions,
            _format: super::super::provider_adapters::ApiFormat,
        ) -> Result<
            super::super::provider_adapters::UpstreamRequest,
            super::super::provider_adapters::AdapterError,
        > {
            Err(
                super::super::provider_adapters::AdapterError::InvalidRequest(
                    "MockAdapter does not support upstream requests".to_string(),
                ),
            )
        }
        fn extract_usage(
            &self,
            _response_body: &serde_json::Value,
        ) -> Option<super::super::provider_execution::TokenUsage> {
            None
        }
        fn apply_zdr_overrides(&self, body: &mut serde_json::Value) {
            if let Some(obj) = body.as_object_mut() {
                obj.insert("store".to_string(), json!(false));
            }
        }
    }

    #[test]
    fn off_mode_skips_nothing() {
        let enforcer = ZdrEnforcer::new(ZdrMode::Off);
        assert!(!enforcer.should_skip_cache());
        assert!(!enforcer.should_strip_event_bodies());
    }

    #[test]
    fn passthrough_mode_skips_cache() {
        let enforcer = ZdrEnforcer::new(ZdrMode::Passthrough);
        assert!(enforcer.should_skip_cache());
        assert!(!enforcer.should_strip_event_bodies());
    }

    #[test]
    fn strict_mode_strips_everything() {
        let enforcer = ZdrEnforcer::new(ZdrMode::Strict);
        assert!(enforcer.should_skip_cache());
        assert!(enforcer.should_strip_event_bodies());
    }

    #[test]
    fn apply_to_request_sets_store_false() {
        let enforcer = ZdrEnforcer::new(ZdrMode::Passthrough);
        let adapter = MockAdapter;
        let mut body = json!({"model": "gpt-5.4-mini", "messages": []});
        enforcer.apply_to_request(&mut body, &adapter);
        assert_eq!(body["store"], json!(false));
    }

    #[test]
    fn sanitize_event_strips_bodies_in_strict() {
        let enforcer = ZdrEnforcer::new(ZdrMode::Strict);
        let mut payload = json!({
            "event_type": "llm_call",
            "request_body": {"messages": [{"role": "user", "content": "secret"}]},
            "response_body": {"choices": []},
            "latency_ms": 200
        });
        enforcer.sanitize_event_payload(&mut payload);
        assert!(payload.get("request_body").is_none());
        assert!(payload.get("response_body").is_none());
        assert!(payload.get("latency_ms").is_some());
    }

    #[test]
    fn sanitize_event_strips_prompt_and_completion_in_strict() {
        let enforcer = ZdrEnforcer::new(ZdrMode::Strict);
        let mut payload = json!({
            "prompt": "secret prompt",
            "completion": "secret completion",
            "model": "gpt-4"
        });
        enforcer.sanitize_event_payload(&mut payload);
        assert!(payload.get("prompt").is_none());
        assert!(payload.get("completion").is_none());
        assert!(payload.get("model").is_some());
    }

    #[test]
    fn sanitize_strict_preserves_accounting_and_decision_evidence() {
        let enforcer = ZdrEnforcer::new(ZdrMode::Strict);
        let mut payload = json!({
            "request_body": {"messages": [{"role": "user", "content": "secret"}]},
            "response_body": {"content": "secret"},
            "prompt": "secret",
            "completion": "secret",
            "input_tokens": 21,
            "output_tokens": 7,
            "total_tokens": 28,
            "cached_input_tokens": 3,
            "total_cost": 0.0042,
            "policy_version": 12,
            "policy_sha256": "abc123",
            "decision": "allow",
            "deny_reason": null,
            "reservation_id": "33333333-3333-3333-3333-333333333333",
            "request_id": "req-1",
            "latency_ms": 180
        });
        enforcer.sanitize_event_payload(&mut payload);
        assert!(payload.get("request_body").is_none());
        assert!(payload.get("response_body").is_none());
        assert!(payload.get("prompt").is_none());
        assert!(payload.get("completion").is_none());
        assert_eq!(payload["input_tokens"], 21);
        assert_eq!(payload["output_tokens"], 7);
        assert_eq!(payload["total_tokens"], 28);
        assert_eq!(payload["cached_input_tokens"], 3);
        assert_eq!(payload["total_cost"], 0.0042);
        assert_eq!(payload["policy_version"], 12);
        assert_eq!(payload["policy_sha256"], "abc123");
        assert_eq!(payload["decision"], "allow");
        assert_eq!(
            payload["reservation_id"],
            "33333333-3333-3333-3333-333333333333"
        );
        assert_eq!(payload["request_id"], "req-1");
        assert_eq!(payload["latency_ms"], 180);
    }

    #[test]
    fn sanitize_event_passthrough_preserves_bodies() {
        let enforcer = ZdrEnforcer::new(ZdrMode::Passthrough);
        let mut payload = json!({
            "request_body": "kept",
            "response_body": "kept"
        });
        enforcer.sanitize_event_payload(&mut payload);
        assert!(payload.get("request_body").is_some());
        assert!(payload.get("response_body").is_some());
    }

    #[test]
    fn sanitize_event_off_preserves_bodies() {
        let enforcer = ZdrEnforcer::new(ZdrMode::Off);
        let mut payload = json!({
            "request_body": "kept",
            "response_body": "kept"
        });
        enforcer.sanitize_event_payload(&mut payload);
        assert!(payload.get("request_body").is_some());
    }

    #[test]
    fn apply_to_request_off_mode_no_op() {
        let enforcer = ZdrEnforcer::new(ZdrMode::Off);
        let adapter = MockAdapter;
        let mut body = json!({"model": "gpt-4"});
        enforcer.apply_to_request(&mut body, &adapter);
        assert!(body.get("store").is_none());
    }

    #[test]
    fn apply_to_request_strict_mode_sets_store_false() {
        let enforcer = ZdrEnforcer::new(ZdrMode::Strict);
        let adapter = MockAdapter;
        let mut body = json!({"model": "gpt-4"});
        enforcer.apply_to_request(&mut body, &adapter);
        assert_eq!(body["store"], json!(false));
    }

    #[test]
    fn mode_accessor() {
        let enforcer = ZdrEnforcer::new(ZdrMode::Passthrough);
        assert_eq!(*enforcer.mode(), ZdrMode::Passthrough);
    }

    #[test]
    fn sanitize_non_object_no_panic() {
        let enforcer = ZdrEnforcer::new(ZdrMode::Strict);
        let mut payload = json!("string payload");
        enforcer.sanitize_event_payload(&mut payload);
        assert_eq!(payload, json!("string payload"));
    }

    #[test]
    fn sanitize_null_no_panic() {
        let enforcer = ZdrEnforcer::new(ZdrMode::Strict);
        let mut payload = json!(null);
        enforcer.sanitize_event_payload(&mut payload);
    }

    #[test]
    fn sanitize_array_no_panic() {
        let enforcer = ZdrEnforcer::new(ZdrMode::Strict);
        let mut payload = json!([1, 2, 3]);
        enforcer.sanitize_event_payload(&mut payload);
    }
}
