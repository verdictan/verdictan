// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Terminal-path release guards for audit capacity and funding.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

/// Releases unused durable-audit capacity on every terminal path.
///
/// Drop and explicit [`Self::release`] are idempotent. The host callback runs
/// at most once so early returns, stage failures, and successful completion
/// all return unused capacity exactly once.
pub struct AuditCapacityGuard {
    release_fn: Option<Box<dyn FnOnce() + Send>>,
    released: bool,
    release_counter: Option<Arc<AtomicUsize>>,
}

impl AuditCapacityGuard {
    /// Build a guard that invokes `release_fn` exactly once on terminal release.
    pub fn new<F>(release_fn: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        Self {
            release_fn: Some(Box::new(release_fn)),
            released: false,
            release_counter: None,
        }
    }

    /// Test/helper constructor that also increments a shared release counter.
    pub fn with_counter<F>(counter: Arc<AtomicUsize>, release_fn: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        Self {
            release_fn: Some(Box::new(release_fn)),
            released: false,
            release_counter: Some(counter),
        }
    }

    /// Whether unused capacity has already been returned.
    pub fn is_released(&self) -> bool {
        self.released
    }

    /// Explicitly release unused capacity. Safe to call multiple times.
    pub fn release(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        if let Some(counter) = &self.release_counter {
            counter.fetch_add(1, Ordering::SeqCst);
        }
        if let Some(release_fn) = self.release_fn.take() {
            release_fn();
        }
    }
}

impl Drop for AuditCapacityGuard {
    fn drop(&mut self) {
        self.release();
    }
}

/// Releases an unused budget/funding reservation on every terminal path.
///
/// Drop and explicit [`Self::release`] are idempotent.
pub struct FundingReservationGuard {
    release_fn: Option<Box<dyn FnOnce() + Send>>,
    released: bool,
    release_counter: Option<Arc<AtomicUsize>>,
    settled: Arc<AtomicBool>,
}

impl FundingReservationGuard {
    /// Build a guard that invokes `release_fn` exactly once unless settled.
    pub fn new<F>(release_fn: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        Self {
            release_fn: Some(Box::new(release_fn)),
            released: false,
            release_counter: None,
            settled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Test/helper constructor that also increments a shared release counter.
    pub fn with_counter<F>(counter: Arc<AtomicUsize>, release_fn: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        Self {
            release_fn: Some(Box::new(release_fn)),
            released: false,
            release_counter: Some(counter),
            settled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Mark the reservation as settled so Drop does not release unused funds.
    pub fn mark_settled(&self) {
        self.settled.store(true, Ordering::SeqCst);
    }

    pub fn is_released(&self) -> bool {
        self.released
    }

    pub fn is_settled(&self) -> bool {
        self.settled.load(Ordering::SeqCst)
    }

    /// Explicitly release unused funding. No-op after settle or prior release.
    pub fn release(&mut self) {
        if self.released || self.settled.load(Ordering::SeqCst) {
            return;
        }
        self.released = true;
        if let Some(counter) = &self.release_counter {
            counter.fetch_add(1, Ordering::SeqCst);
        }
        if let Some(release_fn) = self.release_fn.take() {
            release_fn();
        }
    }
}

impl Drop for FundingReservationGuard {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_guard_releases_exactly_once_on_drop() {
        let counter = Arc::new(AtomicUsize::new(0));
        let observed = Arc::new(AtomicUsize::new(0));
        {
            let observed = Arc::clone(&observed);
            let mut guard = AuditCapacityGuard::with_counter(Arc::clone(&counter), move || {
                observed.fetch_add(1, Ordering::SeqCst);
            });
            guard.release();
            guard.release();
        }
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(observed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn funding_guard_skips_release_after_settle() {
        let counter = Arc::new(AtomicUsize::new(0));
        let observed = Arc::new(AtomicUsize::new(0));
        {
            let observed = Arc::clone(&observed);
            let guard = FundingReservationGuard::with_counter(Arc::clone(&counter), move || {
                observed.fetch_add(1, Ordering::SeqCst);
            });
            guard.mark_settled();
        }
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        assert_eq!(observed.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn funding_guard_releases_on_terminal_drop() {
        let counter = Arc::new(AtomicUsize::new(0));
        let observed = Arc::new(AtomicUsize::new(0));
        {
            let observed = Arc::clone(&observed);
            let _guard = FundingReservationGuard::with_counter(Arc::clone(&counter), move || {
                observed.fetch_add(1, Ordering::SeqCst);
            });
        }
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(observed.load(Ordering::SeqCst), 1);
    }
}
