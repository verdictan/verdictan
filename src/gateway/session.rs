// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GatewayGitContext {
    pub repo: Option<String>,
    pub branch: Option<String>,
    pub commit: Option<String>,
}

impl GatewayGitContext {
    pub fn new(repo: Option<&str>, branch: Option<&str>, commit: Option<&str>) -> Option<Self> {
        let repo = normalize_text(repo);
        let branch = normalize_text(branch);
        let commit = normalize_text(commit);

        if repo.is_none() && branch.is_none() && commit.is_none() {
            return None;
        }

        Some(Self {
            repo,
            branch,
            commit,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct GatewaySessionContext {
    pub session_id: String,
    pub scope: String,
    pub _org_id: Option<String>,
    pub user_id: Option<String>,
    pub team_id: Option<String>,
    pub _key_id: Option<String>,
    pub agent_id: Option<String>,
    pub conversation_id: Option<String>,
    pub gateway_execution_session_id: Option<String>,
    pub git_context: Option<GatewayGitContext>,
    pub context_plan_hash: Option<String>,
}

#[allow(clippy::too_many_arguments)]
fn derive_session_context(
    org_id: Option<&str>,
    user_id: Option<&str>,
    team_id: Option<&str>,
    key_id: Option<&str>,
    gateway_id: Option<&str>,
    agent_id: Option<&str>,
    conversation_id: Option<&str>,
    gateway_execution_session_id: Option<&str>,
) -> Option<GatewaySessionContext> {
    derive_session_context_with_git_context(
        org_id,
        user_id,
        team_id,
        key_id,
        gateway_id,
        agent_id,
        conversation_id,
        gateway_execution_session_id,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn derive_session_context_with_git_context(
    org_id: Option<&str>,
    user_id: Option<&str>,
    team_id: Option<&str>,
    key_id: Option<&str>,
    gateway_id: Option<&str>,
    agent_id: Option<&str>,
    conversation_id: Option<&str>,
    gateway_execution_session_id: Option<&str>,
    git_context: Option<GatewayGitContext>,
) -> Option<GatewaySessionContext> {
    let org_id = org_id.map(str::trim).filter(|value| !value.is_empty())?;
    let user_id = normalize_text(user_id);
    let team_id = normalize_text(team_id);
    let key_id = normalize_text(key_id);
    let agent_id = normalize_text(agent_id);
    let gateway_id = gateway_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("gateway");
    let conversation_id = normalize_text(conversation_id);
    let gateway_execution_session_id = normalize_text(gateway_execution_session_id);
    let git_context = GatewayGitContext::new(
        git_context
            .as_ref()
            .and_then(|context| context.repo.as_deref()),
        git_context
            .as_ref()
            .and_then(|context| context.branch.as_deref()),
        git_context
            .as_ref()
            .and_then(|context| context.commit.as_deref()),
    );
    let scope = if team_id.is_some() {
        "team"
    } else if user_id.is_some() {
        "user"
    } else {
        "org"
    }
    .to_string();

    // When a conversation_id is provided, use it for deterministic session
    // grouping and cross-request recall. When absent, fall back to a
    // per-request UUID so that access-key traffic still appears in the history
    // list without attempting recall (IMP-004).
    let git_seed = git_context
        .as_ref()
        .map(|context| {
            format!(
                ":git:{}:{}:{}",
                context.repo.clone().unwrap_or_default(),
                context.branch.clone().unwrap_or_default(),
                context.commit.clone().unwrap_or_default(),
            )
        })
        .unwrap_or_default();
    let (seed, effective_conversation_id) = if let Some(ref conv_id) = conversation_id {
        (
            format!(
                "history:{}:{}:{}:{}:{}:runner:{}:conv:{}{}",
                org_id,
                team_id.clone().unwrap_or_default(),
                user_id.clone().unwrap_or_default(),
                agent_id.clone().unwrap_or_default(),
                gateway_id,
                gateway_execution_session_id.clone().unwrap_or_default(),
                conv_id,
                git_seed,
            ),
            Some(conv_id.clone()),
        )
    } else {
        // No conversation_id: generate a unique per-request session so the
        // entry is captured in history but recall is not attempted.
        let request_nonce = uuid::Uuid::new_v4().to_string();
        (
            format!(
                "history:{}:{}:{}:{}:{}:runner:{}:nonce:{}{}",
                org_id,
                team_id.clone().unwrap_or_default(),
                user_id.clone().unwrap_or_default(),
                agent_id.clone().unwrap_or_default(),
                gateway_id,
                gateway_execution_session_id.clone().unwrap_or_default(),
                request_nonce,
                git_seed,
            ),
            None,
        )
    };
    let session_id = deterministic_uuid_from_seed(&seed);

    Some(GatewaySessionContext {
        session_id,
        scope,
        _org_id: Some(org_id.to_string()),
        user_id,
        team_id,
        _key_id: key_id,
        agent_id,
        conversation_id: effective_conversation_id,
        gateway_execution_session_id,
        git_context,
        context_plan_hash: None,
    })
}

fn normalize_text(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|candidate| !candidate.is_empty())
        .map(ToOwned::to_owned)
}

fn deterministic_uuid_from_seed(seed: &str) -> String {
    let mut bytes = [0u8; 16];
    let digest = Sha256::digest(seed.as_bytes());
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes).to_string()
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
    fn derive_session_context_returns_none_without_org() {
        let result =
            derive_session_context(None, Some("user1"), None, None, None, None, None, None);
        assert!(result.is_none());
    }

    #[test]
    fn derive_session_context_returns_none_for_empty_org() {
        let result =
            derive_session_context(Some(""), Some("user1"), None, None, None, None, None, None);
        assert!(result.is_none());
    }

    #[test]
    fn derive_session_context_returns_none_for_whitespace_org() {
        let result = derive_session_context(
            Some("  "),
            Some("user1"),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(result.is_none());
    }

    #[test]
    fn derive_session_context_org_only_scope_is_org() {
        let ctx =
            derive_session_context(Some("org1"), None, None, None, None, None, None, None).unwrap();
        assert_eq!(ctx.scope, "org");
        assert!(ctx.user_id.is_none());
        assert!(ctx.team_id.is_none());
    }

    #[test]
    fn derive_session_context_with_user_scope_is_user() {
        let ctx = derive_session_context(
            Some("org1"),
            Some("user1"),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(ctx.scope, "user");
        assert_eq!(ctx.user_id.as_deref(), Some("user1"));
    }

    #[test]
    fn derive_session_context_with_team_scope_is_team() {
        let ctx = derive_session_context(
            Some("org1"),
            Some("user1"),
            Some("team1"),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(ctx.scope, "team");
        assert_eq!(ctx.team_id.as_deref(), Some("team1"));
    }

    #[test]
    fn derive_session_context_deterministic_with_conversation_id() {
        let ctx1 = derive_session_context(
            Some("org1"),
            Some("user1"),
            None,
            None,
            None,
            None,
            Some("conv-123"),
            None,
        )
        .unwrap();
        let ctx2 = derive_session_context(
            Some("org1"),
            Some("user1"),
            None,
            None,
            None,
            None,
            Some("conv-123"),
            None,
        )
        .unwrap();
        assert_eq!(ctx1.session_id, ctx2.session_id);
        assert_eq!(ctx1.conversation_id.as_deref(), Some("conv-123"));
    }

    #[test]
    fn derive_session_context_trims_inputs() {
        let ctx = derive_session_context(
            Some("  org1  "),
            Some("  user1  "),
            Some("  team1  "),
            Some("  key1  "),
            Some("  gw1  "),
            Some("  agent1  "),
            Some("  conv1  "),
            Some("  session1  "),
        )
        .unwrap();
        assert_eq!(ctx.user_id.as_deref(), Some("user1"));
        assert_eq!(ctx.team_id.as_deref(), Some("team1"));
        assert_eq!(ctx.agent_id.as_deref(), Some("agent1"));
        assert_eq!(ctx.conversation_id.as_deref(), Some("conv1"));
        assert_eq!(
            ctx.gateway_execution_session_id.as_deref(),
            Some("session1")
        );
    }

    #[test]
    fn derive_session_context_empty_strings_treated_as_none() {
        let ctx = derive_session_context(
            Some("org1"),
            Some(""),
            Some(""),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(ctx.scope, "org");
        assert!(ctx.user_id.is_none());
        assert!(ctx.team_id.is_none());
    }

    #[test]
    fn deterministic_uuid_from_seed_is_consistent() {
        let a = deterministic_uuid_from_seed("test-seed");
        let b = deterministic_uuid_from_seed("test-seed");
        assert_eq!(a, b);
    }

    #[test]
    fn deterministic_uuid_from_seed_different_seeds_differ() {
        let a = deterministic_uuid_from_seed("seed-a");
        let b = deterministic_uuid_from_seed("seed-b");
        assert_ne!(a, b);
    }

    #[test]
    fn deterministic_uuid_from_seed_is_valid_uuid() {
        let id = deterministic_uuid_from_seed("some-seed");
        assert!(uuid::Uuid::parse_str(&id).is_ok());
    }

    #[test]
    fn deterministic_uuid_from_seed_is_version_5() {
        let id = deterministic_uuid_from_seed("version-check");
        let parsed = uuid::Uuid::parse_str(&id).unwrap();
        assert_eq!(parsed.get_version_num(), 5);
    }

    #[test]
    fn derive_session_context_populates_agent_id() {
        let ctx = derive_session_context(
            Some("org1"),
            Some("user1"),
            None,
            None,
            None,
            Some("agent-abc"),
            Some("conv-1"),
            None,
        )
        .unwrap();
        assert_eq!(ctx.agent_id.as_deref(), Some("agent-abc"));
    }

    #[test]
    fn derive_session_context_gateway_execution_session_id() {
        let ctx = derive_session_context(
            Some("org1"),
            None,
            None,
            None,
            None,
            None,
            Some("conv-1"),
            Some("exec-sess-1"),
        )
        .unwrap();
        assert_eq!(
            ctx.gateway_execution_session_id.as_deref(),
            Some("exec-sess-1")
        );
    }
}
