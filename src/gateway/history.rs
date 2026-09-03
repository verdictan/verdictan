// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use super::{declarative_config::HistoryRuntimeConfig, session::GatewaySessionContext};

#[derive(Clone)]
pub struct HistoryService {
    client: reqwest::Client,
    gateway_client: Option<reqwest::Client>,
    api_base: String,
    config: HistoryRuntimeConfig,
    write_semaphore: Arc<tokio::sync::Semaphore>,
    write_drops: Arc<AtomicU64>,
}

#[derive(Clone, Debug)]
pub(crate) struct HistoryEntryPayload {
    pub gateway_id: String,
    pub provider_id: Option<String>,
    pub model: Option<String>,
    pub decision: String,
    pub request_payload: serde_json::Value,
    pub response_payload: serde_json::Value,
    pub agent_id: Option<String>,
    pub token_usage: serde_json::Value,
    pub entry_kind: String,
    pub is_streaming_completion: bool,
}

impl HistoryService {
    pub(crate) fn new(
        client: reqwest::Client,
        gateway_client: Option<reqwest::Client>,
        api_base: String,
        config: HistoryRuntimeConfig,
    ) -> Self {
        Self {
            client,
            gateway_client,
            api_base,
            config,
            write_semaphore: Arc::new(tokio::sync::Semaphore::new(128)),
            write_drops: Arc::new(AtomicU64::new(0)),
        }
    }

    pub(crate) fn include_blocked(&self) -> bool {
        self.config.include_blocked
    }

    pub(crate) fn enqueue_history_entry(
        &self,
        request_id: &str,
        traceparent: &str,
        session: GatewaySessionContext,
        payload: HistoryEntryPayload,
    ) {
        if self.config.mode == "disabled" {
            return;
        }

        let permit = match self.write_semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                self.write_drops.fetch_add(1, Ordering::Relaxed);
                tracing::warn!("history forwarding backpressure — dropping history entry");
                return;
            }
        };

        let client = self.client.clone();
        let gateway_client = self.gateway_client.clone();
        let api_base = self.api_base.clone();
        let history_cfg = self.config.clone();
        let request_id = request_id.to_string();
        let traceparent = traceparent.to_string();

        tokio::spawn(async move {
            let _permit = permit;

            let gateway_org_id = session
                ._org_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let use_gateway_history = gateway_client.is_some();
            let gateway_org_id = if use_gateway_history {
                match gateway_org_id {
                    Some(org_id) => Some(org_id),
                    None => {
                        tracing::warn!("history write skipped: connected gateway missing org_id");
                        return;
                    }
                }
            } else {
                None
            };

            let history_client = if use_gateway_history {
                match gateway_client.as_ref() {
                    Some(client) => client,
                    None => {
                        tracing::warn!(
                            "history write skipped: connected gateway missing service-token client"
                        );
                        return;
                    }
                }
            } else {
                &client
            };
            let create_session_body = build_create_session_body(
                &session,
                payload.agent_id.as_deref(),
                &history_cfg.mode,
                gateway_org_id,
                use_gateway_history,
            );
            let create_session_url = if use_gateway_history {
                join_url(&api_base, "/v1/gateway/history/sessions")
            } else {
                join_url(&api_base, "/v1/history/sessions")
            };

            if let Err(error) = post_json(
                history_client,
                &create_session_url,
                &request_id,
                &traceparent,
                &create_session_body,
            )
            .await
            {
                tracing::error!(error = %error, "history session ensure failed");
                return;
            }

            let mut token_usage = payload.token_usage;
            if payload.is_streaming_completion {
                if let Some(obj) = token_usage.as_object_mut() {
                    obj.insert("streaming".to_string(), serde_json::Value::Bool(true));
                }
            }

            let entry_body = if use_gateway_history {
                let org_id = gateway_org_id.unwrap_or_default();
                serde_json::json!({
                    "org_id": org_id,
                    "decision": payload.decision,
                    "request_payload": payload.request_payload,
                    "response_payload": payload.response_payload,
                    "provider_id": payload.provider_id,
                    "model": payload.model,
                    "gateway_id": payload.gateway_id,
                    "agent_id": payload.agent_id,
                    "token_usage": token_usage,
                    "entry_kind": payload.entry_kind,
                })
            } else {
                serde_json::json!({
                    "decision": payload.decision,
                    "request_payload": payload.request_payload,
                    "response_payload": payload.response_payload,
                    "provider_id": payload.provider_id,
                    "model": payload.model,
                    "gateway_id": payload.gateway_id,
                    "agent_id": payload.agent_id,
                    "token_usage": token_usage,
                    "entry_kind": payload.entry_kind,
                })
            };
            let entry_url = if use_gateway_history {
                join_url(
                    &api_base,
                    &format!(
                        "/v1/gateway/history/sessions/{}/entries",
                        session.session_id
                    ),
                )
            } else {
                join_url(
                    &api_base,
                    &format!("/v1/history/sessions/{}/entries", session.session_id),
                )
            };

            if let Err(error) = post_json(
                history_client,
                &entry_url,
                &request_id,
                &traceparent,
                &entry_body,
            )
            .await
            {
                tracing::error!(error = %error, "history entry write-back failed");
            }
        });
    }
}

fn build_create_session_body(
    session: &GatewaySessionContext,
    payload_agent_id: Option<&str>,
    capture_mode: &str,
    gateway_org_id: Option<&str>,
    use_gateway_history: bool,
) -> serde_json::Value {
    let git_context = session.git_context.as_ref();
    let agent_id = session
        .agent_id
        .clone()
        .or_else(|| payload_agent_id.map(ToOwned::to_owned));

    if use_gateway_history {
        serde_json::json!({
            "org_id": gateway_org_id.unwrap_or_default(),
            "session_id": session.session_id,
            "scope": session.scope,
            "user_id": session.user_id,
            "team_id": session.team_id,
            "agent_id": agent_id,
            "conversation_id": session.conversation_id,
            "capture_mode": capture_mode,
            "repo": git_context.and_then(|context| context.repo.clone()),
            "branch": git_context.and_then(|context| context.branch.clone()),
            "commit": git_context.and_then(|context| context.commit.clone()),
        })
    } else {
        serde_json::json!({
            "session_id": session.session_id,
            "scope": session.scope,
            "user_id": session.user_id,
            "team_id": session.team_id,
            "agent_id": agent_id,
            "conversation_id": session.conversation_id,
            "capture_mode": capture_mode,
            "repo": git_context.and_then(|context| context.repo.clone()),
            "branch": git_context.and_then(|context| context.branch.clone()),
            "commit": git_context.and_then(|context| context.commit.clone()),
        })
    }
}

async fn post_json(
    client: &reqwest::Client,
    url: &str,
    request_id: &str,
    traceparent: &str,
    body: &serde_json::Value,
) -> anyhow::Result<()> {
    let response = client
        .post(url)
        .header("X-Request-Id", request_id)
        .header("traceparent", traceparent)
        .json(body)
        .send()
        .await?;
    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        // ADR-007: classify machine route errors for structured diagnostics.
        anyhow::bail!(
            "{}",
            super::machine_route_error::classify_and_format("history/sessions", status, &text)
        );
    }
    Ok(())
}

fn join_url(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    format!("{base}/{path}")
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
    fn join_url_basic() {
        assert_eq!(
            join_url("https://api.example.com", "/v1/history"),
            "https://api.example.com/v1/history"
        );
    }

    #[test]
    fn join_url_strips_trailing_slash() {
        assert_eq!(
            join_url("https://api.example.com/", "v1/history"),
            "https://api.example.com/v1/history"
        );
    }

    #[test]
    fn build_create_session_body_includes_gateway_git_scope() {
        let session = GatewaySessionContext {
            session_id: "sess-1".to_string(),
            scope: "team".to_string(),
            user_id: Some("user-1".to_string()),
            team_id: Some("team-1".to_string()),
            agent_id: None,
            conversation_id: Some("conv-1".to_string()),
            _org_id: Some("org-1".to_string()),
            _key_id: None,
            context_plan_hash: None,
            gateway_execution_session_id: None,
            git_context: Some(crate::gateway::session::GatewayGitContext {
                repo: Some("cloudposse/terratest".to_string()),
                branch: Some("master".to_string()),
                commit: Some("511d77a94dc6c465f2b913e6beb87e86ea2746ad".to_string()),
            }),
        };

        let body = build_create_session_body(
            &session,
            Some("agent-from-payload"),
            "raw",
            Some("org-1"),
            true,
        );

        assert_eq!(body["org_id"], "org-1");
        assert_eq!(body["session_id"], "sess-1");
        assert_eq!(body["agent_id"], "agent-from-payload");
        assert_eq!(body["repo"], "cloudposse/terratest");
        assert_eq!(body["branch"], "master");
        assert_eq!(body["commit"], "511d77a94dc6c465f2b913e6beb87e86ea2746ad");
    }

    #[test]
    fn join_url_strips_leading_slash() {
        assert_eq!(
            join_url("https://api.example.com", "v1/history"),
            "https://api.example.com/v1/history"
        );
    }

    #[test]
    fn join_url_double_slashes() {
        assert_eq!(
            join_url("https://api.example.com/", "/v1/history"),
            "https://api.example.com/v1/history"
        );
    }

    #[test]
    fn new_history_service_include_blocked() {
        let config = HistoryRuntimeConfig {
            enabled: true,
            mode: "enabled".to_string(),
            include_blocked: true,
        };
        let service = HistoryService::new(
            reqwest::Client::new(),
            None,
            "https://api.example.com".to_string(),
            config,
        );
        assert!(service.include_blocked());
    }

    #[test]
    fn new_history_service_exclude_blocked() {
        let config = HistoryRuntimeConfig {
            enabled: true,
            mode: "enabled".to_string(),
            include_blocked: false,
        };
        let service = HistoryService::new(
            reqwest::Client::new(),
            None,
            "https://api.example.com".to_string(),
            config,
        );
        assert!(!service.include_blocked());
    }

    #[test]
    fn enqueue_history_entry_disabled_mode_returns_immediately() {
        let config = HistoryRuntimeConfig {
            enabled: true,
            mode: "disabled".to_string(),
            include_blocked: false,
        };
        let service = HistoryService::new(
            reqwest::Client::new(),
            None,
            "https://api.example.com".to_string(),
            config,
        );
        let session = GatewaySessionContext {
            session_id: "sess-1".to_string(),
            scope: "org".to_string(),
            user_id: None,
            team_id: None,
            agent_id: None,
            conversation_id: None,
            _org_id: None,
            _key_id: None,
            context_plan_hash: None,
            gateway_execution_session_id: None,
            git_context: None,
        };
        let payload = HistoryEntryPayload {
            gateway_id: "gw-1".to_string(),
            provider_id: Some("openai".to_string()),
            model: Some("gpt-4".to_string()),
            decision: "allowed".to_string(),
            request_payload: serde_json::json!({}),
            response_payload: serde_json::json!({}),
            agent_id: None,
            token_usage: serde_json::json!({}),
            entry_kind: "completion".to_string(),
            is_streaming_completion: false,
        };
        service.enqueue_history_entry("req-1", "tp-1", session, payload);
    }

    #[test]
    fn history_entry_payload_debug() {
        let payload = HistoryEntryPayload {
            gateway_id: "gw".to_string(),
            provider_id: None,
            model: None,
            decision: "blocked".to_string(),
            request_payload: serde_json::json!(null),
            response_payload: serde_json::json!(null),
            agent_id: Some("agent-1".to_string()),
            token_usage: serde_json::json!({"total": 0}),
            entry_kind: "chat".to_string(),
            is_streaming_completion: true,
        };
        let debug_str = format!("{:?}", payload);
        assert!(debug_str.contains("gw"));
        assert!(debug_str.contains("blocked"));
        assert!(debug_str.contains("agent-1"));
    }

    #[test]
    fn history_service_clone() {
        let config = HistoryRuntimeConfig {
            enabled: true,
            mode: "enabled".to_string(),
            include_blocked: true,
        };
        let service = HistoryService::new(
            reqwest::Client::new(),
            Some(reqwest::Client::new()),
            "https://api.example.com".to_string(),
            config,
        );
        let cloned = service.clone();
        assert!(cloned.include_blocked());
    }

    #[test]
    fn join_url_empty_base() {
        assert_eq!(join_url("", "path"), "/path");
    }

    #[test]
    fn join_url_empty_path() {
        assert_eq!(
            join_url("https://api.example.com", ""),
            "https://api.example.com/"
        );
    }

    #[test]
    fn history_entry_payload_clone() {
        let payload = HistoryEntryPayload {
            gateway_id: "gw".to_string(),
            provider_id: None,
            model: None,
            decision: "allowed".to_string(),
            request_payload: serde_json::json!({}),
            response_payload: serde_json::json!({}),
            agent_id: None,
            token_usage: serde_json::json!({}),
            entry_kind: "completion".to_string(),
            is_streaming_completion: false,
        };
        let cloned = payload.clone();
        assert_eq!(cloned.gateway_id, "gw");
        assert_eq!(cloned.decision, "allowed");
    }

    #[tokio::test]
    async fn enqueue_history_entry_semaphore_based_backpressure() {
        let config = HistoryRuntimeConfig {
            enabled: true,
            mode: "full".to_string(),
            include_blocked: true,
        };
        let service = HistoryService::new(
            reqwest::Client::new(),
            None,
            "https://unreachable.example.com".to_string(),
            config,
        );
        let session = GatewaySessionContext {
            session_id: "sess-bp".to_string(),
            scope: "org".to_string(),
            user_id: None,
            team_id: None,
            agent_id: None,
            conversation_id: None,
            _org_id: Some("org-bp".to_string()),
            _key_id: None,
            context_plan_hash: None,
            gateway_execution_session_id: None,
            git_context: None,
        };
        let payload = HistoryEntryPayload {
            gateway_id: "gw-bp".to_string(),
            provider_id: Some("openai".to_string()),
            model: Some("gpt-4o".to_string()),
            decision: "allowed".to_string(),
            request_payload: serde_json::json!({"model": "gpt-4o"}),
            response_payload: serde_json::json!({"choices": []}),
            agent_id: None,
            token_usage: serde_json::json!({"prompt_tokens": 10, "completion_tokens": 5}),
            entry_kind: "chat".to_string(),
            is_streaming_completion: false,
        };
        // Should not panic — the entry gets queued or dropped gracefully.
        service.enqueue_history_entry("req-bp", "tp-bp", session, payload);
    }

    #[test]
    fn history_service_with_gateway_client_disabled_mode() {
        let config = HistoryRuntimeConfig {
            enabled: true,
            mode: "disabled".to_string(),
            include_blocked: false,
        };
        let service = HistoryService::new(
            reqwest::Client::new(),
            Some(reqwest::Client::new()),
            "https://unreachable.example.com".to_string(),
            config,
        );
        let session = GatewaySessionContext {
            session_id: "sess-gw-disabled".to_string(),
            scope: "org".to_string(),
            user_id: None,
            team_id: None,
            agent_id: None,
            conversation_id: None,
            _org_id: Some("org-gw".to_string()),
            _key_id: None,
            context_plan_hash: None,
            gateway_execution_session_id: None,
            git_context: None,
        };
        let payload = HistoryEntryPayload {
            gateway_id: "gw-connected".to_string(),
            provider_id: None,
            model: None,
            decision: "allowed".to_string(),
            request_payload: serde_json::json!(null),
            response_payload: serde_json::json!(null),
            agent_id: None,
            token_usage: serde_json::json!({}),
            entry_kind: "embedding".to_string(),
            is_streaming_completion: false,
        };
        service.enqueue_history_entry("req-gw", "tp-gw", session, payload);
    }

    #[test]
    fn history_entry_all_optional_fields_populated() {
        let payload = HistoryEntryPayload {
            gateway_id: "gw-full".to_string(),
            provider_id: Some("anthropic".to_string()),
            model: Some("claude-3-opus".to_string()),
            decision: "blocked".to_string(),
            request_payload: serde_json::json!({"messages": [{"role": "user", "content": "hi"}]}),
            response_payload: serde_json::json!({"error": "policy_violation"}),
            agent_id: Some("agent-full".to_string()),
            token_usage: serde_json::json!({"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}),
            entry_kind: "chat".to_string(),
            is_streaming_completion: true,
        };
        assert_eq!(payload.gateway_id, "gw-full");
        assert_eq!(payload.provider_id.as_deref(), Some("anthropic"));
        assert_eq!(payload.model.as_deref(), Some("claude-3-opus"));
        assert_eq!(payload.decision, "blocked");
        assert!(payload.is_streaming_completion);
    }

    #[test]
    fn join_url_with_path_segments() {
        assert_eq!(
            join_url(
                "https://api.example.com",
                "/v1/gateway/history/sessions/sess-1/entries"
            ),
            "https://api.example.com/v1/gateway/history/sessions/sess-1/entries"
        );
    }

    #[test]
    fn join_url_base_with_double_slash_and_path_with_double_slash() {
        assert_eq!(
            join_url("https://api.example.com//", "//v1/history"),
            "https://api.example.com/v1/history"
        );
    }

    #[test]
    fn history_runtime_config_variants() {
        let metadata = HistoryRuntimeConfig {
            enabled: true,
            mode: "metadata".to_string(),
            include_blocked: false,
        };
        assert_eq!(metadata.mode, "metadata");

        let summary = HistoryRuntimeConfig {
            enabled: true,
            mode: "summary".to_string(),
            include_blocked: true,
        };
        assert_eq!(summary.mode, "summary");
        assert!(summary.include_blocked);
    }

    #[test]
    fn session_context_all_fields() {
        let ctx = GatewaySessionContext {
            session_id: "sess-all".to_string(),
            scope: "team".to_string(),
            user_id: Some("user-x".to_string()),
            team_id: Some("team-y".to_string()),
            agent_id: Some("agent-z".to_string()),
            conversation_id: Some("conv-w".to_string()),
            _org_id: Some("org-v".to_string()),
            _key_id: Some("key-u".to_string()),
            context_plan_hash: Some("hash-t".to_string()),
            gateway_execution_session_id: Some("exec-s".to_string()),
            git_context: None,
        };
        assert_eq!(ctx.session_id, "sess-all");
        assert_eq!(ctx.scope, "team");
        assert_eq!(ctx.user_id.as_deref(), Some("user-x"));
        assert_eq!(ctx.team_id.as_deref(), Some("team-y"));
        assert_eq!(ctx.agent_id.as_deref(), Some("agent-z"));
        assert_eq!(ctx.conversation_id.as_deref(), Some("conv-w"));
    }
}
