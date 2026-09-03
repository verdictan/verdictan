// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::sync::Arc;

pub mod l1;
pub mod l2;
pub mod precompute;
pub mod semantic;

pub use semantic::*;

#[derive(Clone)]
pub struct CacheStack {
    pub semantic: Arc<semantic::ProviderResponseCache>,
    pub l1: Arc<l1::ContextPlanL1Cache>,
    pub l2: Arc<l2::ContextPlanL2Cache>,
    pub precompute: Option<precompute::ContextPlanPrecomputeHandle>,
}

impl CacheStack {
    pub fn new(
        semantic: Arc<semantic::ProviderResponseCache>,
        l1: Arc<l1::ContextPlanL1Cache>,
        l2: Arc<l2::ContextPlanL2Cache>,
        precompute: Option<precompute::ContextPlanPrecomputeHandle>,
    ) -> Self {
        Self {
            semantic,
            l1,
            l2,
            precompute,
        }
    }
}
