// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

/// In-process token vault for the regulated-execution privacy pipeline.
///
/// Stores `token_id → original_value` mappings produced during edge
/// tokenization so that detokenization can be performed after provider
/// response, subject to execution-profile permissions.
///
/// Design constraints:
/// - Per-request lifecycle: create → populate during input phase →
///   optionally detokenize during output phase → `clear` before
///   the request context is released.
/// - No persistence to disk or external systems. Regulated profiles
///   keep everything in process memory per.
/// - `clear` is the caller's responsibility; the vault does NOT
///   auto-clear on drop (a drop-guard pattern is left to future work).
///
/// Part of the regulated runtime privacy pipeline.
use std::collections::HashMap;

use crate::gateway::data_classification::DataClass;

/// An entry stored in the vault: original value and its data class.
#[derive(Debug, Clone)]
pub struct VaultEntry {
    /// The original (sensitive) string value.
    pub value: String,
    /// The data class assigned during classification.
    pub data_class: DataClass,
}

/// In-memory token-to-value store for a single request lifetime.
#[derive(Debug, Default)]
pub struct TokenVault {
    entries: HashMap<String, VaultEntry>,
    /// Monotonic counter for generating compact sequential token IDs when a
    /// UUID library is unavailable. The IDs have the form `t<seq>r<random>`.
    counter: u64,
}

impl TokenVault {
    /// Create an empty vault.
    pub fn new() -> Self {
        Self::default()
    }

    /// Store `value` in the vault and return the generated token ID.
    ///
    /// The returned token ID is guaranteed to be unique within this vault
    /// instance. Callers embed it inside the placeholder string.
    pub fn store(&mut self, value: String, data_class: DataClass) -> String {
        let token_id = self.next_token_id();
        self.entries
            .insert(token_id.clone(), VaultEntry { value, data_class });
        token_id
    }

    /// Retrieve the original value for `token_id`.
    ///
    /// Returns `None` when the token is not present (e.g. vault was cleared
    /// or this token belongs to a different request).
    pub fn retrieve(&self, token_id: &str) -> Option<&str> {
        self.entries.get(token_id).map(|e| e.value.as_str())
    }

    /// Retrieve the full vault entry for `token_id`, including data class.
    fn retrieve_entry(&self, token_id: &str) -> Option<&VaultEntry> {
        self.entries.get(token_id)
    }

    /// Number of tokens currently stored.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when the vault contains no tokens.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Erase all stored values.
    ///
    /// Callers MUST invoke this at the end of every request so sensitive data
    /// does not linger in heap memory across request boundaries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Iterate over all entries in unspecified order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &VaultEntry)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn next_token_id(&mut self) -> String {
        self.counter += 1;
        // Mix counter with a fast pseudo-random component derived from the
        // counter itself so sequential IDs are not trivially predictable.
        // This is not cryptographically secure; its purpose is operational
        // uniqueness within a single request, not security.
        let r = self.counter.wrapping_mul(0x517c_c1b7_2722_0a95)
            ^ self.counter.wrapping_shl(32)
            ^ 0xf4cf_f3d3_d140_1e76;
        format!("t{:08x}r{:08x}", self.counter, r & 0xffff_ffff)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
    use crate::gateway::data_classification::DataClass;

    #[test]
    fn new_vault_is_empty() {
        let vault = TokenVault::new();
        assert!(vault.is_empty());
        assert_eq!(vault.len(), 0);
    }

    #[test]
    fn store_and_retrieve() {
        let mut vault = TokenVault::new();
        let token = vault.store("secret-value".into(), DataClass::SensitivePii);
        assert_eq!(vault.retrieve(&token), Some("secret-value"));
        assert_eq!(vault.len(), 1);
        assert!(!vault.is_empty());
    }

    #[test]
    fn retrieve_entry_returns_data_class() {
        let mut vault = TokenVault::new();
        let token = vault.store("phi-data".into(), DataClass::SensitivePhi);
        let entry = vault.retrieve_entry(&token).unwrap();
        assert_eq!(entry.value, "phi-data");
        assert_eq!(entry.data_class, DataClass::SensitivePhi);
    }

    #[test]
    fn retrieve_missing_token_returns_none() {
        let vault = TokenVault::new();
        assert!(vault.retrieve("nonexistent").is_none());
        assert!(vault.retrieve_entry("nonexistent").is_none());
    }

    #[test]
    fn clear_removes_all_entries() {
        let mut vault = TokenVault::new();
        vault.store("a".into(), DataClass::Unclassified);
        vault.store("b".into(), DataClass::Unclassified);
        assert_eq!(vault.len(), 2);
        vault.clear();
        assert!(vault.is_empty());
        assert_eq!(vault.len(), 0);
    }

    #[test]
    fn iter_yields_all_entries() {
        let mut vault = TokenVault::new();
        vault.store("x".into(), DataClass::Unclassified);
        vault.store("y".into(), DataClass::FinancialData);
        let entries: Vec<_> = vault.iter().collect();
        assert_eq!(entries.len(), 2);
        let values: Vec<&str> = entries.iter().map(|(_, e)| e.value.as_str()).collect();
        assert!(values.contains(&"x"));
        assert!(values.contains(&"y"));
    }

    #[test]
    fn default_creates_empty_vault() {
        let vault = TokenVault::default();
        assert!(vault.is_empty());
    }

    #[test]
    fn retrieve_after_clear_returns_none() {
        let mut vault = TokenVault::new();
        let token = vault.store("temp".into(), DataClass::Unclassified);
        vault.clear();
        assert!(vault.retrieve(&token).is_none());
    }
}
