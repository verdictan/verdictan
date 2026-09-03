// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::sync::{LazyLock, Mutex};

use indexmap::IndexMap;

use super::agent_context::{AppliedAgentContext, SelectedContextItemTelemetry};

pub const CONTEXT_PACK_CACHE_MAX_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct ContextPackCacheKey {
    pub team_id: Option<String>,
    pub agent_id: String,
    pub git_repo: String,
    pub git_branch: String,
    pub pack_hash: String,
}

#[derive(Clone, Debug)]
struct ContextPackCacheEntry {
    applied: AppliedAgentContext,
    size_bytes: usize,
}

#[derive(Debug)]
pub struct ContextPackCache {
    max_bytes: usize,
    total_bytes: usize,
    entries: IndexMap<ContextPackCacheKey, ContextPackCacheEntry>,
}

impl ContextPackCache {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            total_bytes: 0,
            entries: IndexMap::new(),
        }
    }

    pub fn get(&mut self, key: &ContextPackCacheKey) -> Option<AppliedAgentContext> {
        let entry = self.entries.shift_remove(key)?;
        let applied = entry.applied.clone();
        self.entries.insert(key.clone(), entry);
        Some(applied)
    }

    pub fn insert(&mut self, key: ContextPackCacheKey, applied: AppliedAgentContext) {
        let size_bytes = estimate_applied_context_bytes(&applied);
        if size_bytes > self.max_bytes {
            return;
        }

        if let Some(existing) = self.entries.shift_remove(&key) {
            self.total_bytes = self.total_bytes.saturating_sub(existing.size_bytes);
        }

        self.total_bytes = self.total_bytes.saturating_add(size_bytes);
        self.entries.insert(
            key,
            ContextPackCacheEntry {
                applied,
                size_bytes,
            },
        );
        self.evict_if_needed();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    fn evict_if_needed(&mut self) {
        while self.total_bytes > self.max_bytes {
            let Some((_, entry)) = self.entries.shift_remove_index(0) else {
                self.total_bytes = 0;
                break;
            };
            self.total_bytes = self.total_bytes.saturating_sub(entry.size_bytes);
        }
    }
}

static SHARED_CONTEXT_PACK_CACHE: LazyLock<Mutex<ContextPackCache>> =
    LazyLock::new(|| Mutex::new(ContextPackCache::new(CONTEXT_PACK_CACHE_MAX_BYTES)));

pub fn shared_context_pack_cache() -> &'static Mutex<ContextPackCache> {
    &SHARED_CONTEXT_PACK_CACHE
}

pub fn estimate_applied_context_bytes(applied: &AppliedAgentContext) -> usize {
    applied.block.len()
        + applied.telemetry.plan_hash.len()
        + applied
            .telemetry
            .selected_item_ids
            .iter()
            .map(String::len)
            .sum::<usize>()
        + applied
            .telemetry
            .selected_receipt_ids
            .iter()
            .map(String::len)
            .sum::<usize>()
        + applied
            .telemetry
            .selected_hierarchy_lanes
            .iter()
            .map(String::len)
            .sum::<usize>()
        + applied
            .telemetry
            .selected_items
            .iter()
            .map(estimate_selected_item_bytes)
            .sum::<usize>()
        + applied.telemetry.pack_hash.as_deref().map_or(0, str::len)
        + applied
            .telemetry
            .manifest_hash
            .as_deref()
            .map_or(0, str::len)
        + applied
            .telemetry
            .ranking_policy_version
            .as_deref()
            .map_or(0, str::len)
        + applied
            .telemetry
            .visibility_digest
            .as_deref()
            .map_or(0, str::len)
        + 512
}

fn estimate_selected_item_bytes(item: &SelectedContextItemTelemetry) -> usize {
    item.item_id.len()
        + item.item_type.len()
        + item
            .source_history_session_id
            .as_deref()
            .map_or(0, str::len)
        + item.hierarchy_lane.as_deref().map_or(0, str::len)
        + item.receipt_id.as_deref().map_or(0, str::len)
        + item
            .receipt_verification_status
            .as_deref()
            .map_or(0, str::len)
        + 128
}
