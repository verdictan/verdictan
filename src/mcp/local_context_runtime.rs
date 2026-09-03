// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Session-scoped local MCP runtime state for context-fabric reads.

use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, RwLock},
};

use crate::gateway::crdt_sync::CrdtSyncDriver;

static SHARED_LOCAL_CONTEXT_RUNTIME_REGISTRY: LazyLock<LocalContextRuntimeRegistry> =
    LazyLock::new(LocalContextRuntimeRegistry::default);

pub fn shared_local_context_runtime_registry() -> &'static LocalContextRuntimeRegistry {
    &SHARED_LOCAL_CONTEXT_RUNTIME_REGISTRY
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalContextSessionScope {
    pub team_id: Option<String>,
    pub repo: Option<String>,
    pub branch: Option<String>,
    pub commit: Option<String>,
    pub working_directory: Option<String>,
}

impl LocalContextSessionScope {
    fn normalized(self) -> Option<Self> {
        let normalized = Self {
            team_id: normalize_optional_string(self.team_id),
            repo: normalize_optional_string(self.repo),
            branch: normalize_optional_string(self.branch),
            commit: normalize_optional_string(self.commit),
            working_directory: normalize_optional_string(self.working_directory),
        };

        (!normalized.is_empty()).then_some(normalized)
    }

    fn is_empty(&self) -> bool {
        self.team_id.is_none()
            && self.repo.is_none()
            && self.branch.is_none()
            && self.commit.is_none()
            && self.working_directory.is_none()
    }
}

#[derive(Clone, Default)]
pub struct LocalContextSessionRuntime {
    scope: Option<LocalContextSessionScope>,
    crdt_sync_driver: Option<CrdtSyncDriver>,
}

impl LocalContextSessionRuntime {
    pub fn scope(&self) -> Option<LocalContextSessionScope> {
        self.scope.clone()
    }

    pub fn crdt_sync_driver(&self) -> Option<CrdtSyncDriver> {
        self.crdt_sync_driver.clone()
    }

    fn is_empty(&self) -> bool {
        self.scope.is_none() && self.crdt_sync_driver.is_none()
    }
}

#[derive(Clone, Default)]
pub struct LocalContextRuntimeRegistry {
    inner: Arc<RwLock<HashMap<String, LocalContextSessionRuntime>>>,
}

impl LocalContextRuntimeRegistry {
    pub fn session(&self, session_id: impl Into<String>) -> LocalContextSessionHandle {
        LocalContextSessionHandle {
            registry: self.clone(),
            session_id: session_id.into(),
        }
    }

    fn runtime(&self, session_id: &str) -> Option<LocalContextSessionRuntime> {
        #[allow(clippy::expect_used)]
        self.inner
            .read()
            .expect("local context runtime registry lock")
            .get(session_id)
            .cloned()
    }

    fn update_session<F>(&self, session_id: &str, update: F)
    where
        F: FnOnce(&mut LocalContextSessionRuntime),
    {
        #[allow(clippy::expect_used)]
        let mut guard = self
            .inner
            .write()
            .expect("local context runtime registry lock");
        let should_remove = {
            let entry = guard.entry(session_id.to_string()).or_default();
            update(entry);
            entry.is_empty()
        };
        if should_remove {
            guard.remove(session_id);
        }
    }

    fn remove_session(&self, session_id: &str) -> Option<LocalContextSessionRuntime> {
        #[allow(clippy::expect_used)]
        self.inner
            .write()
            .expect("local context runtime registry lock")
            .remove(session_id)
    }
}

#[derive(Clone)]
pub struct LocalContextSessionHandle {
    registry: LocalContextRuntimeRegistry,
    session_id: String,
}

impl LocalContextSessionHandle {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn runtime(&self) -> Option<LocalContextSessionRuntime> {
        self.registry.runtime(&self.session_id)
    }

    pub fn scope(&self) -> Option<LocalContextSessionScope> {
        self.runtime().and_then(|runtime| runtime.scope())
    }

    pub fn set_scope(&self, scope: Option<LocalContextSessionScope>) {
        let scope = scope.and_then(LocalContextSessionScope::normalized);
        self.registry
            .update_session(&self.session_id, |entry| entry.scope = scope);
    }

    pub fn crdt_sync_driver(&self) -> Option<CrdtSyncDriver> {
        self.runtime()
            .and_then(|runtime| runtime.crdt_sync_driver())
    }

    pub fn bind_crdt_sync_driver(&self, crdt_sync_driver: Option<CrdtSyncDriver>) {
        self.registry.update_session(&self.session_id, |entry| {
            entry.crdt_sync_driver = crdt_sync_driver
        });
    }

    pub fn clear(&self) -> Option<LocalContextSessionRuntime> {
        self.registry.remove_session(&self.session_id)
    }
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
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

    use std::sync::Arc;

    use tokio::sync::RwLock;

    use super::*;
    use crate::gateway::{
        crdt::ContextCrdt,
        crdt_sync::{CrdtSyncDriver, PeerSyncConfig},
    };

    #[test]
    fn session_scope_round_trips_through_cloneable_handle() {
        let registry = LocalContextRuntimeRegistry::default();
        let handle = registry.session("session-1");

        handle.set_scope(Some(LocalContextSessionScope {
            team_id: Some(" team-1 ".to_string()),
            repo: Some(" verdictan/verdictan ".to_string()),
            branch: Some(" main ".to_string()),
            commit: Some(" abc123 ".to_string()),
            working_directory: Some(" /workspace/verdictan ".to_string()),
        }));

        let clone = handle.clone();
        assert_eq!(
            clone.scope(),
            Some(LocalContextSessionScope {
                team_id: Some("team-1".to_string()),
                repo: Some("verdictan/verdictan".to_string()),
                branch: Some("main".to_string()),
                commit: Some("abc123".to_string()),
                working_directory: Some("/workspace/verdictan".to_string()),
            })
        );
        assert_eq!(clone.session_id(), "session-1");
    }

    #[test]
    fn binding_driver_preserves_scope_and_supports_unbind() {
        let registry = LocalContextRuntimeRegistry::default();
        let handle = registry.session("session-2");
        let driver = test_crdt_sync_driver("replica-a");

        handle.set_scope(Some(LocalContextSessionScope {
            repo: Some("verdictan/verdictan".to_string()),
            branch: Some("main".to_string()),
            ..LocalContextSessionScope::default()
        }));
        handle.bind_crdt_sync_driver(Some(driver.clone()));

        let bound_driver = handle.crdt_sync_driver().expect("bound driver");
        assert!(Arc::ptr_eq(&bound_driver.state(), &driver.state()));
        assert_eq!(
            handle.scope(),
            Some(LocalContextSessionScope {
                repo: Some("verdictan/verdictan".to_string()),
                branch: Some("main".to_string()),
                ..LocalContextSessionScope::default()
            })
        );

        handle.bind_crdt_sync_driver(None);
        assert!(handle.crdt_sync_driver().is_none());
        assert!(handle.scope().is_some());
    }

    #[test]
    fn empty_scope_and_missing_driver_remove_session_entry() {
        let registry = LocalContextRuntimeRegistry::default();
        let handle = registry.session("session-3");
        let driver = test_crdt_sync_driver("replica-b");

        handle.bind_crdt_sync_driver(Some(driver));
        handle.set_scope(Some(LocalContextSessionScope {
            repo: Some("verdictan/verdictan".to_string()),
            ..LocalContextSessionScope::default()
        }));
        assert!(handle.runtime().is_some());

        handle.set_scope(None);
        assert!(handle.runtime().is_some());

        handle.bind_crdt_sync_driver(None);
        assert!(handle.runtime().is_none());

        handle.set_scope(Some(LocalContextSessionScope {
            repo: Some("   ".to_string()),
            branch: Some("".to_string()),
            ..LocalContextSessionScope::default()
        }));
        assert!(handle.runtime().is_none());
    }

    #[test]
    fn clear_removes_session_and_returns_snapshot() {
        let registry = LocalContextRuntimeRegistry::default();
        let handle = registry.session("session-4");
        let driver = test_crdt_sync_driver("replica-c");

        handle.set_scope(Some(LocalContextSessionScope {
            team_id: Some("team-4".to_string()),
            ..LocalContextSessionScope::default()
        }));
        handle.bind_crdt_sync_driver(Some(driver));

        let cleared = handle.clear().expect("cleared runtime");
        assert_eq!(
            cleared.scope(),
            Some(LocalContextSessionScope {
                team_id: Some("team-4".to_string()),
                ..LocalContextSessionScope::default()
            })
        );
        assert!(cleared.crdt_sync_driver().is_some());
        assert!(handle.runtime().is_none());
    }

    fn test_crdt_sync_driver(replica_id: &str) -> CrdtSyncDriver {
        let state = Arc::new(RwLock::new(ContextCrdt::new(replica_id).unwrap()));
        CrdtSyncDriver::new(state, PeerSyncConfig::default()).unwrap()
    }
}
