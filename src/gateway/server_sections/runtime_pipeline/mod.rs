// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Runtime pipeline helpers (split for module-size gate).
mod part1;
mod part2;
mod shadow_queue;

pub use part1::*;
pub use part2::*;
pub use shadow_queue::*;
