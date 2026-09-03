// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Gateway admission control with per-region and per-family concurrency limits.
//!
//! The [`AdmissionController`] gates incoming requests before they reach
//! upstream dispatch. When capacity is exhausted the gateway returns a
//! deterministic shed response instead of queuing indefinitely.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const DEFAULT_MAX_CONCURRENT_PER_REGION: usize = 1000;
const DEFAULT_MAX_CONCURRENT_PER_FAMILY: usize = 5000;
const DEFAULT_MAX_QUEUE_WAIT_MS: u64 = 30_000;

#[derive(Debug)]
pub enum AdmissionDenied {
    RegionAtCapacity { region_key: String, limit: usize },
    FamilyAtCapacity { family_key: String, limit: usize },
    QueueTimeout { waited_ms: u64 },
}

impl std::fmt::Display for AdmissionDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegionAtCapacity { region_key, limit } => {
                write!(f, "region {region_key} at capacity ({limit})")
            }
            Self::FamilyAtCapacity { family_key, limit } => {
                write!(f, "family {family_key} at capacity ({limit})")
            }
            Self::QueueTimeout { waited_ms } => {
                write!(f, "admission queue timeout after {waited_ms}ms")
            }
        }
    }
}

/// RAII guard that decrements the region and family counters on drop.
pub struct AdmissionPermit {
    region_counter: Arc<AtomicUsize>,
    family_counter: Arc<AtomicUsize>,
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        self.region_counter.fetch_sub(1, Ordering::Relaxed);
        self.family_counter.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Clone)]
pub struct AdmissionController {
    max_concurrent_per_region: usize,
    max_concurrent_per_family: usize,
    #[allow(dead_code)]
    max_queue_wait_ms: u64,
    region_counters: Arc<Mutex<HashMap<String, Arc<AtomicUsize>>>>,
    family_counters: Arc<Mutex<HashMap<String, Arc<AtomicUsize>>>>,
}

impl AdmissionController {
    pub fn new(
        max_concurrent_per_region: Option<usize>,
        max_concurrent_per_family: Option<usize>,
        max_queue_wait_ms: Option<u64>,
    ) -> Self {
        Self {
            max_concurrent_per_region: max_concurrent_per_region
                .unwrap_or(DEFAULT_MAX_CONCURRENT_PER_REGION),
            max_concurrent_per_family: max_concurrent_per_family
                .unwrap_or(DEFAULT_MAX_CONCURRENT_PER_FAMILY),
            max_queue_wait_ms: max_queue_wait_ms.unwrap_or(DEFAULT_MAX_QUEUE_WAIT_MS),
            region_counters: Arc::new(Mutex::new(HashMap::new())),
            family_counters: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn counter_for(map: &Mutex<HashMap<String, Arc<AtomicUsize>>>, key: &str) -> Arc<AtomicUsize> {
        #[allow(clippy::expect_used)]
        let mut guard = map.lock().expect("admission counter lock");
        guard
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .clone()
    }

    pub fn try_admit(
        &self,
        region_key: &str,
        family_key: &str,
    ) -> Result<AdmissionPermit, AdmissionDenied> {
        let region_counter = Self::counter_for(&self.region_counters, region_key);
        let family_counter = Self::counter_for(&self.family_counters, family_key);

        let prev_region = region_counter.fetch_add(1, Ordering::Relaxed);
        if prev_region >= self.max_concurrent_per_region {
            region_counter.fetch_sub(1, Ordering::Relaxed);
            return Err(AdmissionDenied::RegionAtCapacity {
                region_key: region_key.to_string(),
                limit: self.max_concurrent_per_region,
            });
        }

        let prev_family = family_counter.fetch_add(1, Ordering::Relaxed);
        if prev_family >= self.max_concurrent_per_family {
            family_counter.fetch_sub(1, Ordering::Relaxed);
            region_counter.fetch_sub(1, Ordering::Relaxed);
            return Err(AdmissionDenied::FamilyAtCapacity {
                family_key: family_key.to_string(),
                limit: self.max_concurrent_per_family,
            });
        }

        Ok(AdmissionPermit {
            region_counter,
            family_counter,
        })
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

    #[test]
    fn admits_within_limits() {
        let controller = AdmissionController::new(Some(2), Some(3), None);
        let _p1 = controller.try_admit("eu", "family-a").unwrap();
        let _p2 = controller.try_admit("eu", "family-a").unwrap();
        assert!(matches!(
            controller.try_admit("eu", "family-a"),
            Err(AdmissionDenied::RegionAtCapacity { .. })
        ));
    }

    #[test]
    fn permit_drop_releases_capacity() {
        let controller = AdmissionController::new(Some(1), Some(10), None);
        {
            let _p = controller.try_admit("eu", "family-a").unwrap();
            assert!(controller.try_admit("eu", "family-a").is_err());
        }
        let _p2 = controller.try_admit("eu", "family-a").unwrap();
    }

    #[test]
    fn family_limit_enforced_across_regions() {
        let controller = AdmissionController::new(Some(100), Some(2), None);
        let _p1 = controller.try_admit("eu", "family-a").unwrap();
        let _p2 = controller.try_admit("us", "family-a").unwrap();
        assert!(matches!(
            controller.try_admit("ap", "family-a"),
            Err(AdmissionDenied::FamilyAtCapacity { .. })
        ));
    }

    #[test]
    fn different_families_tracked_independently() {
        let controller = AdmissionController::new(Some(100), Some(1), None);
        let _p1 = controller.try_admit("eu", "family-a").unwrap();
        let _p2 = controller.try_admit("eu", "family-b").unwrap();
    }

    #[test]
    fn display_formats_are_descriptive() {
        let denied = AdmissionDenied::RegionAtCapacity {
            region_key: "eu".to_string(),
            limit: 100,
        };
        assert!(format!("{denied}").contains("eu"));

        let denied = AdmissionDenied::QueueTimeout { waited_ms: 5000 };
        assert!(format!("{denied}").contains("5000"));
    }
}
