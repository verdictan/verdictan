// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CrdtError {
    #[error("replica id must not be empty")]
    EmptyReplicaId,
    #[error("failed to serialize crdt state: {0}")]
    Serialize(#[from] Box<bincode::ErrorKind>),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HlcTimestamp {
    pub wall_time_ms: i64,
    pub logical: u32,
    pub node_id: String,
}

impl HlcTimestamp {
    pub fn zero(node_id: impl Into<String>) -> Self {
        Self {
            wall_time_ms: 0,
            logical: 0,
            node_id: node_id.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HlcClock {
    node_id: String,
    last: HlcTimestamp,
}

impl HlcClock {
    pub fn new(node_id: impl Into<String>) -> Result<Self, CrdtError> {
        let node_id = node_id.into();
        if node_id.trim().is_empty() {
            return Err(CrdtError::EmptyReplicaId);
        }
        Ok(Self {
            last: HlcTimestamp::zero(node_id.clone()),
            node_id,
        })
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn tick(&mut self, now_ms: i64) -> HlcTimestamp {
        if now_ms > self.last.wall_time_ms {
            self.last = HlcTimestamp {
                wall_time_ms: now_ms,
                logical: 0,
                node_id: self.node_id.clone(),
            };
        } else {
            self.last = HlcTimestamp {
                wall_time_ms: self.last.wall_time_ms,
                logical: self.last.logical.saturating_add(1),
                node_id: self.node_id.clone(),
            };
        }
        self.last.clone()
    }

    pub fn tick_now(&mut self) -> HlcTimestamp {
        self.tick(unix_timestamp_millis())
    }

    pub fn observe(&mut self, remote: &HlcTimestamp, now_ms: i64) -> HlcTimestamp {
        let last = self.last.clone();
        let max_wall_time = now_ms.max(last.wall_time_ms).max(remote.wall_time_ms);
        let logical = if max_wall_time == last.wall_time_ms && max_wall_time == remote.wall_time_ms
        {
            last.logical.max(remote.logical).saturating_add(1)
        } else if max_wall_time == last.wall_time_ms {
            last.logical.saturating_add(1)
        } else if max_wall_time == remote.wall_time_ms {
            remote.logical.saturating_add(1)
        } else {
            0
        };

        self.last = HlcTimestamp {
            wall_time_ms: max_wall_time,
            logical,
            node_id: self.node_id.clone(),
        };
        self.last.clone()
    }

    pub fn observe_now(&mut self, remote: &HlcTimestamp) -> HlcTimestamp {
        self.observe(remote, unix_timestamp_millis())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrSet {
    adds: BTreeMap<String, BTreeSet<HlcTimestamp>>,
    tombstones: BTreeMap<String, BTreeMap<HlcTimestamp, HlcTimestamp>>,
}

impl OrSet {
    pub fn add(&mut self, element: impl Into<String>, tag: HlcTimestamp) -> bool {
        self.adds.entry(element.into()).or_default().insert(tag)
    }

    pub fn remove(&mut self, element: &str, removed_at: HlcTimestamp) -> usize {
        let visible_tags = self.visible_tags(element);
        if visible_tags.is_empty() {
            return 0;
        }
        let tombstones = self.tombstones.entry(element.to_string()).or_default();
        let mut inserted = 0;
        for tag in visible_tags {
            if tombstones.insert(tag, removed_at.clone()).is_none() {
                inserted += 1;
            }
        }
        inserted
    }

    pub fn is_visible(&self, element: &str) -> bool {
        !self.visible_tags(element).is_empty()
    }

    pub fn visible_tags(&self, element: &str) -> Vec<HlcTimestamp> {
        let adds = match self.adds.get(element) {
            Some(adds) => adds,
            None => return Vec::new(),
        };
        let tombstones = self.tombstones.get(element);
        adds.iter()
            .filter(|tag| {
                tombstones
                    .map(|removed| !removed.contains_key(*tag))
                    .unwrap_or(true)
            })
            .cloned()
            .collect()
    }

    pub fn visible_elements(&self) -> Vec<String> {
        self.adds
            .keys()
            .filter(|element| self.is_visible(element))
            .cloned()
            .collect()
    }

    pub fn adds(&self) -> &BTreeMap<String, BTreeSet<HlcTimestamp>> {
        &self.adds
    }

    pub fn tombstones(&self) -> &BTreeMap<String, BTreeMap<HlcTimestamp, HlcTimestamp>> {
        &self.tombstones
    }

    pub fn merge_in(&mut self, other: &Self) -> OrSetMergeSummary {
        let mut summary = OrSetMergeSummary::default();

        for (element, remote_tags) in &other.adds {
            let local_tags = self.adds.entry(element.clone()).or_default();
            for tag in remote_tags {
                if local_tags.insert(tag.clone()) {
                    summary.added_tags += 1;
                }
            }
        }

        for (element, remote_tombstones) in &other.tombstones {
            let local_tombstones = self.tombstones.entry(element.clone()).or_default();
            for (tag, removed_at) in remote_tombstones {
                let replace = local_tombstones
                    .get(tag)
                    .map(|existing| removed_at > existing)
                    .unwrap_or(true);
                if replace {
                    if local_tombstones
                        .insert(tag.clone(), removed_at.clone())
                        .is_none()
                    {
                        summary.added_tombstones += 1;
                    } else {
                        summary.updated_tombstones += 1;
                    }
                }
            }
        }

        summary
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OrSetMergeSummary {
    pub added_tags: usize,
    pub added_tombstones: usize,
    pub updated_tombstones: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LwwRegister {
    #[serde(with = "json_value_codec")]
    pub value: Value,
    pub timestamp: HlcTimestamp,
}

impl LwwRegister {
    pub fn merge(local: &Self, remote: &Self) -> Self {
        if remote.timestamp > local.timestamp {
            return remote.clone();
        }
        if remote.timestamp < local.timestamp {
            return local.clone();
        }
        if canonical_json_string(&remote.value) > canonical_json_string(&local.value) {
            remote.clone()
        } else {
            local.clone()
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ContextCrdtState {
    membership: OrSet,
    fields: BTreeMap<String, BTreeMap<String, LwwRegister>>,
}

impl ContextCrdtState {
    pub fn membership(&self) -> &OrSet {
        &self.membership
    }

    pub fn fields(&self) -> &BTreeMap<String, BTreeMap<String, LwwRegister>> {
        &self.fields
    }

    pub fn visible_entry_ids(&self) -> Vec<String> {
        self.membership.visible_elements()
    }

    pub fn visible_len(&self) -> usize {
        self.visible_entry_ids().len()
    }

    pub fn entry_view(&self, entry_id: &str) -> Option<ContextEntryView> {
        if !self.membership.is_visible(entry_id) {
            return None;
        }

        let fields = self
            .fields
            .get(entry_id)
            .map(|values| {
                values
                    .iter()
                    .map(|(field, register)| (field.clone(), register.value.clone()))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        let last_updated = self.latest_visible_timestamp(entry_id)?;

        Some(ContextEntryView {
            entry_id: entry_id.to_string(),
            fields,
            last_updated,
        })
    }

    pub fn local_search(
        &self,
        query: &str,
        scope: &LocalReadScope,
        limit: usize,
    ) -> Vec<ContextEntryView> {
        if limit == 0 {
            return Vec::new();
        }

        let normalized_terms = normalized_terms(query);
        let mut matches = self
            .visible_entry_ids()
            .into_iter()
            .filter_map(|entry_id| self.entry_view(&entry_id))
            .filter(|view| scope.matches(view))
            .filter_map(|view| {
                let haystack = searchable_blob(&view.fields);
                let score = if normalized_terms.is_empty() {
                    1
                } else {
                    normalized_terms
                        .iter()
                        .filter(|term| haystack.contains(term.as_str()))
                        .count()
                };
                if score == 0 {
                    None
                } else {
                    Some((score, view))
                }
            })
            .collect::<Vec<_>>();

        matches.sort_by(|(score_a, view_a), (score_b, view_b)| {
            score_b
                .cmp(score_a)
                .then_with(|| view_b.last_updated.cmp(&view_a.last_updated))
                .then_with(|| view_a.entry_id.cmp(&view_b.entry_id))
        });

        matches
            .into_iter()
            .take(limit)
            .map(|(_, view)| view)
            .collect()
    }

    pub fn local_recent(&self, scope: &LocalReadScope, limit: usize) -> Vec<ContextEntryView> {
        if limit == 0 {
            return Vec::new();
        }

        let mut entries = self
            .visible_entry_ids()
            .into_iter()
            .filter_map(|entry_id| self.entry_view(&entry_id))
            .filter(|view| scope.matches(view))
            .collect::<Vec<_>>();

        entries.sort_by(|left, right| {
            right
                .last_updated
                .cmp(&left.last_updated)
                .then_with(|| left.entry_id.cmp(&right.entry_id))
        });
        entries.truncate(limit);
        entries
    }

    pub fn local_schema_lookup(
        &self,
        schema_key: &str,
        scope: &LocalReadScope,
    ) -> Vec<ContextEntryView> {
        let normalized_key = normalize_ascii(schema_key);
        self.visible_entry_ids()
            .into_iter()
            .filter_map(|entry_id| self.entry_view(&entry_id))
            .filter(|view| scope.matches(view))
            .filter(|view| {
                matches_schema_key(view.fields.get("schema_key"), &normalized_key)
                    || matches_schema_key(view.fields.get("schema_keys"), &normalized_key)
            })
            .collect()
    }

    pub fn merge_in(&mut self, other: &Self) -> MergeSummary {
        let membership = self.membership.merge_in(&other.membership);
        let mut changed_fields = 0;
        let mut inserted_fields = 0;

        for (entry_id, remote_fields) in &other.fields {
            let local_fields = self.fields.entry(entry_id.clone()).or_default();
            for (field_name, remote_register) in remote_fields {
                match local_fields.get(field_name) {
                    Some(local_register) => {
                        let merged = LwwRegister::merge(local_register, remote_register);
                        if merged.timestamp != local_register.timestamp
                            || canonical_json_string(&merged.value)
                                != canonical_json_string(&local_register.value)
                        {
                            local_fields.insert(field_name.clone(), merged);
                            changed_fields += 1;
                        }
                    }
                    None => {
                        local_fields.insert(field_name.clone(), remote_register.clone());
                        inserted_fields += 1;
                    }
                }
            }
        }

        MergeSummary {
            membership,
            changed_fields,
            inserted_fields,
        }
    }

    pub fn merged(&self, other: &Self) -> Self {
        let mut merged = self.clone();
        merged.merge_in(other);
        merged
    }

    pub fn max_timestamp(&self) -> Option<HlcTimestamp> {
        let mut max_timestamp = None;

        for tags in self.membership.adds.values() {
            for tag in tags {
                update_max_timestamp(&mut max_timestamp, tag.clone());
            }
        }
        for removed_tags in self.membership.tombstones.values() {
            for (tag, removed_at) in removed_tags {
                update_max_timestamp(&mut max_timestamp, tag.clone());
                update_max_timestamp(&mut max_timestamp, removed_at.clone());
            }
        }
        for entry_fields in self.fields.values() {
            for register in entry_fields.values() {
                update_max_timestamp(&mut max_timestamp, register.timestamp.clone());
            }
        }

        max_timestamp
    }

    pub fn to_binary(&self) -> Result<Vec<u8>, CrdtError> {
        Ok(bincode::serialize(self)?)
    }

    pub fn from_binary(bytes: &[u8]) -> Result<Self, CrdtError> {
        Ok(bincode::deserialize(bytes)?)
    }

    pub fn compact(&mut self, now_ms: i64, max_age: Duration) -> CompactionSummary {
        let cutoff_ms = cutoff_timestamp_ms(now_ms, max_age);
        let mut summary = CompactionSummary::default();
        let entry_ids = all_entry_ids(&self.membership, &self.fields);

        for entry_id in entry_ids {
            if let Some(tombstones) = self.membership.tombstones.get_mut(&entry_id) {
                let stale_tags = tombstones
                    .iter()
                    .filter(|(_, removed_at)| removed_at.wall_time_ms < cutoff_ms)
                    .map(|(tag, _)| tag.clone())
                    .collect::<Vec<_>>();

                for tag in stale_tags {
                    if tombstones.remove(&tag).is_some() {
                        summary.removed_tombstones += 1;
                    }
                    if let Some(adds) = self.membership.adds.get_mut(&entry_id) {
                        if adds.remove(&tag) {
                            summary.pruned_add_tags += 1;
                        }
                    }
                }
            }

            if self
                .membership
                .tombstones
                .get(&entry_id)
                .map(|tags| tags.is_empty())
                .unwrap_or(false)
            {
                self.membership.tombstones.remove(&entry_id);
            }

            let visible_tags = self.membership.visible_tags(&entry_id);
            if let Some(newest_visible_tag) = visible_tags.iter().max().cloned() {
                if let Some(adds) = self.membership.adds.get_mut(&entry_id) {
                    let removable_tags = adds
                        .iter()
                        .filter(|tag| **tag != newest_visible_tag && tag.wall_time_ms < cutoff_ms)
                        .cloned()
                        .collect::<Vec<_>>();
                    for tag in removable_tags {
                        if adds.remove(&tag) {
                            summary.pruned_add_tags += 1;
                        }
                    }
                }
            }

            let latest_activity = self.latest_any_timestamp(&entry_id);
            if self.membership.visible_tags(&entry_id).is_empty()
                && latest_activity
                    .map(|timestamp| timestamp.wall_time_ms < cutoff_ms)
                    .unwrap_or(false)
            {
                if let Some(registers) = self.fields.remove(&entry_id) {
                    summary.removed_field_registers += registers.len();
                }
                if let Some(adds) = self.membership.adds.remove(&entry_id) {
                    summary.pruned_add_tags += adds.len();
                }
                if let Some(tombstones) = self.membership.tombstones.remove(&entry_id) {
                    summary.removed_tombstones += tombstones.len();
                }
                summary.removed_hidden_entries += 1;
            }
        }

        summary
    }

    fn latest_visible_timestamp(&self, entry_id: &str) -> Option<HlcTimestamp> {
        let mut max_timestamp = None;
        for tag in self.membership.visible_tags(entry_id) {
            update_max_timestamp(&mut max_timestamp, tag);
        }
        if let Some(fields) = self.fields.get(entry_id) {
            for register in fields.values() {
                update_max_timestamp(&mut max_timestamp, register.timestamp.clone());
            }
        }
        max_timestamp
    }

    fn latest_any_timestamp(&self, entry_id: &str) -> Option<HlcTimestamp> {
        let mut max_timestamp = None;
        if let Some(adds) = self.membership.adds.get(entry_id) {
            for tag in adds {
                update_max_timestamp(&mut max_timestamp, tag.clone());
            }
        }
        if let Some(tombstones) = self.membership.tombstones.get(entry_id) {
            for (tag, removed_at) in tombstones {
                update_max_timestamp(&mut max_timestamp, tag.clone());
                update_max_timestamp(&mut max_timestamp, removed_at.clone());
            }
        }
        if let Some(fields) = self.fields.get(entry_id) {
            for register in fields.values() {
                update_max_timestamp(&mut max_timestamp, register.timestamp.clone());
            }
        }
        max_timestamp
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MergeSummary {
    pub membership: OrSetMergeSummary,
    pub changed_fields: usize,
    pub inserted_fields: usize,
}

impl MergeSummary {
    pub fn state_changed(&self) -> bool {
        self.membership.added_tags > 0
            || self.membership.added_tombstones > 0
            || self.membership.updated_tombstones > 0
            || self.changed_fields > 0
            || self.inserted_fields > 0
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompactionSummary {
    pub removed_tombstones: usize,
    pub pruned_add_tags: usize,
    pub removed_hidden_entries: usize,
    pub removed_field_registers: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ContextEntryView {
    pub entry_id: String,
    pub fields: BTreeMap<String, Value>,
    pub last_updated: HlcTimestamp,
}

impl ContextEntryView {
    pub fn field_str(&self, key: &str) -> Option<&str> {
        self.fields.get(key).and_then(Value::as_str)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalReadScope {
    pub repo: Option<String>,
    pub branch: Option<String>,
}

impl LocalReadScope {
    pub fn any() -> Self {
        Self::default()
    }

    pub fn scoped(repo: Option<&str>, branch: Option<&str>) -> Self {
        Self {
            repo: repo.map(str::to_string),
            branch: branch.map(str::to_string),
        }
    }

    fn matches(&self, view: &ContextEntryView) -> bool {
        let repo_matches = self.repo.as_deref().is_none_or(|expected| {
            view.field_str("repo")
                .map(|actual| actual == expected)
                .unwrap_or(false)
        });
        let branch_matches = self.branch.as_deref().is_none_or(|expected| {
            view.field_str("branch")
                .map(|actual| actual == expected)
                .unwrap_or(false)
        });
        repo_matches && branch_matches
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum CrdtMutation {
    UpsertEntry {
        entry_id: String,
        fields: BTreeMap<String, Value>,
        now_ms: Option<i64>,
    },
    SetField {
        entry_id: String,
        field: String,
        value: Value,
        now_ms: Option<i64>,
    },
    RemoveEntry {
        entry_id: String,
        now_ms: Option<i64>,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MutationResult {
    pub changed: bool,
    pub timestamp: Option<HlcTimestamp>,
}

#[derive(Clone, Debug)]
pub struct ContextCrdt {
    replica_id: String,
    clock: HlcClock,
    state: ContextCrdtState,
}

impl ContextCrdt {
    pub fn new(replica_id: impl Into<String>) -> Result<Self, CrdtError> {
        let replica_id = replica_id.into();
        let clock = HlcClock::new(replica_id.clone())?;
        Ok(Self {
            replica_id,
            clock,
            state: ContextCrdtState::default(),
        })
    }

    pub fn replica_id(&self) -> &str {
        &self.replica_id
    }

    pub fn state(&self) -> &ContextCrdtState {
        &self.state
    }

    pub fn snapshot(&self) -> ContextCrdtState {
        self.state.clone()
    }

    pub fn export_binary_state(&self) -> Result<Vec<u8>, CrdtError> {
        self.state.to_binary()
    }

    pub fn merge_binary_state_at(
        &mut self,
        binary_state: &[u8],
        now_ms: i64,
    ) -> Result<MergeSummary, CrdtError> {
        let remote = ContextCrdtState::from_binary(binary_state)?;
        Ok(self.merge_state_at(&remote, now_ms))
    }

    pub fn merge_binary_state(&mut self, binary_state: &[u8]) -> Result<MergeSummary, CrdtError> {
        self.merge_binary_state_at(binary_state, unix_timestamp_millis())
    }

    pub fn merge_state_at(&mut self, remote: &ContextCrdtState, now_ms: i64) -> MergeSummary {
        if let Some(remote_max) = remote.max_timestamp() {
            self.clock.observe(&remote_max, now_ms);
        }
        self.state.merge_in(remote)
    }

    pub fn merge_state(&mut self, remote: &ContextCrdtState) -> MergeSummary {
        self.merge_state_at(remote, unix_timestamp_millis())
    }

    pub fn apply_mutation(&mut self, mutation: CrdtMutation) -> MutationResult {
        match mutation {
            CrdtMutation::UpsertEntry {
                entry_id,
                fields,
                now_ms,
            } => self.upsert_entry(entry_id, fields, now_ms),
            CrdtMutation::SetField {
                entry_id,
                field,
                value,
                now_ms,
            } => self.set_field(entry_id, field, value, now_ms),
            CrdtMutation::RemoveEntry { entry_id, now_ms } => {
                self.remove_entry(entry_id.as_str(), now_ms)
            }
        }
    }

    pub fn upsert_entry(
        &mut self,
        entry_id: impl Into<String>,
        fields: BTreeMap<String, Value>,
        now_ms: Option<i64>,
    ) -> MutationResult {
        let entry_id = entry_id.into();
        let timestamp = self.tick(now_ms);
        let mut changed = false;

        if !self.state.membership.is_visible(&entry_id) {
            changed |= self
                .state
                .membership
                .add(entry_id.clone(), timestamp.clone());
        }

        let registers = self.state.fields.entry(entry_id).or_default();
        for (field, value) in fields {
            let incoming = LwwRegister {
                value,
                timestamp: timestamp.clone(),
            };
            match registers.get(&field) {
                Some(existing) => {
                    let merged = LwwRegister::merge(existing, &incoming);
                    if merged.timestamp != existing.timestamp
                        || canonical_json_string(&merged.value)
                            != canonical_json_string(&existing.value)
                    {
                        registers.insert(field, merged);
                        changed = true;
                    }
                }
                None => {
                    registers.insert(field, incoming);
                    changed = true;
                }
            }
        }

        MutationResult {
            changed,
            timestamp: Some(timestamp),
        }
    }

    pub fn set_field(
        &mut self,
        entry_id: impl Into<String>,
        field: impl Into<String>,
        value: Value,
        now_ms: Option<i64>,
    ) -> MutationResult {
        let entry_id = entry_id.into();
        let timestamp = self.tick(now_ms);
        let mut changed = false;

        if !self.state.membership.is_visible(&entry_id) {
            changed |= self
                .state
                .membership
                .add(entry_id.clone(), timestamp.clone());
        }

        let field_name = field.into();
        let registers = self.state.fields.entry(entry_id).or_default();
        let incoming = LwwRegister {
            value,
            timestamp: timestamp.clone(),
        };

        match registers.get(&field_name) {
            Some(existing) => {
                let merged = LwwRegister::merge(existing, &incoming);
                if merged.timestamp != existing.timestamp
                    || canonical_json_string(&merged.value)
                        != canonical_json_string(&existing.value)
                {
                    registers.insert(field_name, merged);
                    changed = true;
                }
            }
            None => {
                registers.insert(field_name, incoming);
                changed = true;
            }
        }

        MutationResult {
            changed,
            timestamp: Some(timestamp),
        }
    }

    pub fn remove_entry(&mut self, entry_id: &str, now_ms: Option<i64>) -> MutationResult {
        if !self.state.membership.is_visible(entry_id) {
            return MutationResult::default();
        }

        let timestamp = self.tick(now_ms);
        let changed = self.state.membership.remove(entry_id, timestamp.clone()) > 0;
        MutationResult {
            changed,
            timestamp: Some(timestamp),
        }
    }

    pub fn local_search(
        &self,
        query: &str,
        scope: &LocalReadScope,
        limit: usize,
    ) -> Vec<ContextEntryView> {
        self.state.local_search(query, scope, limit)
    }

    pub fn local_recent(&self, scope: &LocalReadScope, limit: usize) -> Vec<ContextEntryView> {
        self.state.local_recent(scope, limit)
    }

    pub fn local_schema_lookup(
        &self,
        schema_key: &str,
        scope: &LocalReadScope,
    ) -> Vec<ContextEntryView> {
        self.state.local_schema_lookup(schema_key, scope)
    }

    pub fn get_local_entry(&self, entry_id: &str) -> Option<ContextEntryView> {
        self.state.entry_view(entry_id)
    }

    pub fn compact_at(&mut self, now_ms: i64, max_age: Duration) -> CompactionSummary {
        self.state.compact(now_ms, max_age)
    }

    pub fn compact_now(&mut self, max_age: Duration) -> CompactionSummary {
        self.compact_at(unix_timestamp_millis(), max_age)
    }

    fn tick(&mut self, now_ms: Option<i64>) -> HlcTimestamp {
        match now_ms {
            Some(now_ms) => self.clock.tick(now_ms),
            None => self.clock.tick_now(),
        }
    }
}

pub fn unix_timestamp_millis() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_millis()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

fn searchable_blob(fields: &BTreeMap<String, Value>) -> String {
    let mut tokens = Vec::new();
    for value in fields.values() {
        flatten_value(value, &mut tokens);
    }
    tokens.join(" ")
}

fn flatten_value(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Null => {}
        Value::Bool(boolean) => out.push(boolean.to_string()),
        Value::Number(number) => out.push(number.to_string()),
        Value::String(text) => out.push(normalize_ascii(text)),
        Value::Array(values) => {
            for value in values {
                flatten_value(value, out);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                flatten_value(value, out);
            }
        }
    }
}

fn matches_schema_key(value: Option<&Value>, normalized_key: &str) -> bool {
    match value {
        Some(Value::String(text)) => normalize_ascii(text) == normalized_key,
        Some(Value::Array(values)) => values.iter().any(|value| {
            value
                .as_str()
                .map(|text| normalize_ascii(text) == normalized_key)
                .unwrap_or(false)
        }),
        _ => false,
    }
}

fn normalized_terms(query: &str) -> Vec<String> {
    normalize_ascii(query)
        .split_whitespace()
        .filter(|term| !term.is_empty())
        .map(str::to_string)
        .collect()
}

fn normalize_ascii(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn canonical_json_string(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

fn update_max_timestamp(slot: &mut Option<HlcTimestamp>, candidate: HlcTimestamp) {
    let should_replace = slot
        .as_ref()
        .map(|current| candidate > *current)
        .unwrap_or(true);
    if should_replace {
        *slot = Some(candidate);
    }
}

fn cutoff_timestamp_ms(now_ms: i64, max_age: Duration) -> i64 {
    let age_ms = i64::try_from(max_age.as_millis()).unwrap_or(i64::MAX);
    now_ms.saturating_sub(age_ms)
}

fn all_entry_ids(
    membership: &OrSet,
    fields: &BTreeMap<String, BTreeMap<String, LwwRegister>>,
) -> BTreeSet<String> {
    membership
        .adds
        .keys()
        .chain(membership.tombstones.keys())
        .chain(fields.keys())
        .cloned()
        .collect()
}

mod json_value_codec {
    use super::*;

    pub fn serialize<S>(value: &Value, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = serde_json::to_string(value).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        serde_json::from_str(&encoded).map_err(serde::de::Error::custom)
    }
}
