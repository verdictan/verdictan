// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

//! Hot-reload notification channel for policy updates.
//!
//! A publisher writes a generation counter to a `tokio::sync::watch` channel
//! when policy content changes. Handlers subscribe and read the latest policy
//! set without restart.

use tokio::sync::watch;
use tracing::debug;

/// Create a new policy reload channel.
///
/// Returns `(sender, receiver)`. The sender goes to the policy update
/// publisher; the receiver is cloned for each handler that needs to react to
/// policy changes.
pub fn channel() -> (watch::Sender<u64>, watch::Receiver<u64>) {
    watch::channel(0)
}

/// Subscribe to policy reload notifications.
///
/// Returns when the generation counter changes. Callers should reload policy
/// state after this returns.
async fn wait_for_update(rx: &mut watch::Receiver<u64>) -> u64 {
    rx.changed().await.ok();
    let gen = *rx.borrow();
    debug!(generation = gen, "Policy reload notification received");
    gen
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

    #[tokio::test]
    async fn channel_delivers_updates() {
        let (tx, mut rx) = channel();
        assert_eq!(*rx.borrow(), 0);

        tx.send(1).unwrap();
        let gen = wait_for_update(&mut rx).await;
        assert_eq!(gen, 1);
    }

    #[tokio::test]
    async fn multiple_receivers_all_notified() {
        let (tx, rx) = channel();
        let mut rx1 = rx.clone();
        let mut rx2 = rx.clone();

        tx.send(42).unwrap();

        let g1 = wait_for_update(&mut rx1).await;
        let g2 = wait_for_update(&mut rx2).await;
        assert_eq!(g1, 42);
        assert_eq!(g2, 42);
    }

    #[tokio::test]
    async fn skips_intermediate_values() {
        let (tx, mut rx) = channel();

        tx.send(1).unwrap();
        tx.send(2).unwrap();
        tx.send(3).unwrap();

        let gen = wait_for_update(&mut rx).await;
        assert_eq!(gen, 3);
    }
}
