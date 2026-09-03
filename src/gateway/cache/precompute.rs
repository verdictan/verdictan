// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::error::CliError;

use super::l1::{
    ContextCacheAuthorization, ContextPlan, ContextPlanL1Cache, ContextPlanPartitionKey,
    ContextPoolMutation,
};
use super::l2::{ContextPlanL2Cache, TopicClusterContext};

pub type ContextPlanSourceFuture =
    Pin<Box<dyn Future<Output = Result<ContextPlanPartitionSnapshot, CliError>> + Send>>;

pub trait ContextPlanSource: Send + Sync + 'static {
    fn recompute_partition(
        &self,
        authorization: ContextCacheAuthorization,
        repo: String,
        branch: String,
    ) -> ContextPlanSourceFuture;
}

pub struct FnContextPlanSource<F> {
    inner: F,
}

impl<F> FnContextPlanSource<F> {
    pub fn new(inner: F) -> Self {
        Self { inner }
    }
}

impl<F, Fut> ContextPlanSource for FnContextPlanSource<F>
where
    F: Fn(ContextCacheAuthorization, String, String) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<ContextPlanPartitionSnapshot, CliError>> + Send + 'static,
{
    fn recompute_partition(
        &self,
        authorization: ContextCacheAuthorization,
        repo: String,
        branch: String,
    ) -> ContextPlanSourceFuture {
        Box::pin((self.inner)(authorization, repo, branch))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextPlanPartitionSnapshot {
    pub repo: String,
    pub branch: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plans: Vec<ContextPlan>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub topic_clusters: Vec<TopicClusterContext>,
}

impl ContextPlanPartitionSnapshot {
    pub fn topics(&self) -> Vec<String> {
        self.topic_clusters
            .iter()
            .map(|cluster| cluster.topic.clone())
            .collect()
    }
}

#[derive(Default)]
struct ContextPlanPrecomputeStatsInner {
    queued_partitions: AtomicU64,
    invalidation_events: AtomicU64,
    completed_recomputes: AtomicU64,
    failed_recomputes: AtomicU64,
    last_recompute_duration_ms: AtomicU64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextPlanPrecomputeStats {
    pub queued_partitions: u64,
    pub invalidation_events: u64,
    pub completed_recomputes: u64,
    pub failed_recomputes: u64,
    pub last_recompute_duration_ms: Option<u64>,
}

#[derive(Clone)]
pub struct ContextPlanPrecomputeHandle {
    tx: mpsc::Sender<ContextPoolMutation>,
    stats: Arc<ContextPlanPrecomputeStatsInner>,
}

impl ContextPlanPrecomputeHandle {
    pub async fn notify(&self, mutation: ContextPoolMutation) -> Result<(), CliError> {
        self.tx.send(mutation).await.map_err(|error| {
            CliError::internal(format!("context precompute worker stopped: {error}"))
        })
    }

    pub fn stats(&self) -> ContextPlanPrecomputeStats {
        let last_duration = self
            .stats
            .last_recompute_duration_ms
            .load(Ordering::Relaxed);
        ContextPlanPrecomputeStats {
            queued_partitions: self.stats.queued_partitions.load(Ordering::Relaxed),
            invalidation_events: self.stats.invalidation_events.load(Ordering::Relaxed),
            completed_recomputes: self.stats.completed_recomputes.load(Ordering::Relaxed),
            failed_recomputes: self.stats.failed_recomputes.load(Ordering::Relaxed),
            last_recompute_duration_ms: if last_duration == 0 {
                None
            } else {
                Some(last_duration)
            },
        }
    }
}

pub struct ContextPlanPrecomputeWorker {
    l1: Arc<ContextPlanL1Cache>,
    l2: Arc<ContextPlanL2Cache>,
    source: Arc<dyn ContextPlanSource>,
    debounce: Duration,
    channel_capacity: usize,
    stats: Arc<ContextPlanPrecomputeStatsInner>,
}

impl ContextPlanPrecomputeWorker {
    pub fn new(
        l1: Arc<ContextPlanL1Cache>,
        l2: Arc<ContextPlanL2Cache>,
        source: Arc<dyn ContextPlanSource>,
        debounce: Duration,
    ) -> Self {
        Self {
            l1,
            l2,
            source,
            debounce,
            channel_capacity: 256,
            stats: Arc::new(ContextPlanPrecomputeStatsInner::default()),
        }
    }

    pub fn with_channel_capacity(mut self, channel_capacity: usize) -> Self {
        self.channel_capacity = channel_capacity.max(1);
        self
    }

    pub fn spawn(self) -> (ContextPlanPrecomputeHandle, JoinHandle<()>) {
        let (tx, mut rx) = mpsc::channel(self.channel_capacity);
        let stats = Arc::clone(&self.stats);
        let handle = ContextPlanPrecomputeHandle {
            tx,
            stats: Arc::clone(&stats),
        };

        let join = tokio::spawn(async move {
            let mut pending = HashMap::<ContextPlanPartitionKey, Instant>::new();
            let mut channel_open = true;

            loop {
                if !channel_open && pending.is_empty() {
                    break;
                }

                let next_deadline = pending.values().copied().min();
                tokio::select! {
                    biased;

                    maybe_mutation = rx.recv(), if channel_open => {
                        match maybe_mutation {
                            Some(mutation) => {
                                if !mutation.authorization.is_complete() {
                                    continue;
                                }
                                stats.invalidation_events.fetch_add(1, Ordering::Relaxed);
                                self.l1.publish_invalidation(mutation.clone());
                                self.l2.apply_mutation(&mutation);
                                pending.insert(mutation.partition_key(), Instant::now() + self.debounce);
                                stats.queued_partitions.store(pending.len() as u64, Ordering::Relaxed);
                            }
                            None => {
                                channel_open = false;
                            }
                        }
                    }

                    _ = async {
                        if let Some(deadline) = next_deadline {
                            tokio::time::sleep_until(deadline).await;
                        }
                    }, if next_deadline.is_some() => {
                        let now = Instant::now();
                        let due = pending
                            .iter()
                            .filter(|(_, deadline)| **deadline <= now)
                            .map(|(partition, _)| partition.clone())
                            .collect::<Vec<_>>();

                        for partition in due {
                            pending.remove(&partition);
                            stats.queued_partitions.store(pending.len() as u64, Ordering::Relaxed);

                            let started = Instant::now();
                            match self
                                .source
                                .recompute_partition(
                                    partition.0.clone(),
                                    partition.1.clone(),
                                    partition.2.clone(),
                                )
                                .await
                            {
                                Ok(snapshot) => {
                                    let repo = if snapshot.repo.trim().is_empty() {
                                        partition.1.clone()
                                    } else {
                                        snapshot.repo.clone()
                                    };
                                    let branch = if snapshot.branch.trim().is_empty() {
                                        partition.2.clone()
                                    } else {
                                        snapshot.branch.clone()
                                    };
                                    let topics = snapshot.topics();
                                    self.l1.replace_partition_plans(
                                        &partition.0,
                                        &repo,
                                        &branch,
                                        snapshot.plans,
                                    );
                                    self.l2.replace_partition_topics(&repo, &branch, topics);
                                    for mut cluster in snapshot.topic_clusters {
                                        if cluster.repo.trim().is_empty() {
                                            cluster.repo = repo.clone();
                                        }
                                        if cluster.branch.trim().is_empty() {
                                            cluster.branch = branch.clone();
                                        }
                                        self.l2.store_topic_cluster(cluster);
                                    }
                                    stats.completed_recomputes.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(error) => {
                                    tracing::warn!(
                                        error = %error,
                                        repo = %partition.1,
                                        branch = %partition.2,
                                        "context plan precompute failed"
                                    );
                                    stats.failed_recomputes.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            stats.last_recompute_duration_ms.store(
                                started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
                                Ordering::Relaxed,
                            );
                        }
                    }
                }
            }
        });

        (handle, join)
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
    use crate::gateway::cache::l1::{
        ContextCacheAuthorization, ContextPlanItem, ContextPoolMutationKind,
    };
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    fn authorization() -> ContextCacheAuthorization {
        ContextCacheAuthorization::new(
            "org-precompute",
            Some("team-precompute".to_string()),
            "authz-v1",
        )
    }

    fn snapshot(
        authorization: ContextCacheAuthorization,
        repo: &str,
        branch: &str,
        query: &str,
        topic: &str,
    ) -> ContextPlanPartitionSnapshot {
        ContextPlanPartitionSnapshot {
            repo: repo.to_string(),
            branch: branch.to_string(),
            plans: vec![ContextPlan::new(
                authorization,
                repo,
                branch,
                query,
                vec![ContextPlanItem {
                    organization_id: String::new(),
                    team_id: None,
                    authorization_version: String::new(),
                    item_id: "item-1".to_string(),
                    content: "shared context".to_string(),
                    token_estimate: 4,
                    citation_required: false,
                    source_kind: Some("manual".to_string()),
                }],
            )],
            topic_clusters: vec![TopicClusterContext::new(repo, branch, topic, vec![])],
        }
    }

    #[tokio::test]
    async fn worker_publishes_l1_invalidation_before_recompute() {
        let l1 = Arc::new(ContextPlanL1Cache::new(16, 1_000_000));
        let l2 = Arc::new(
            ContextPlanL2Cache::new(None, "cache", Duration::from_secs(60), 16, 0.05).expect("l2"),
        );
        let mut receiver = l1.subscribe();
        let source = Arc::new(FnContextPlanSource::new(
            |authorization: ContextCacheAuthorization, repo: String, branch: String| async move {
                Ok(snapshot(authorization, &repo, &branch, "query", "schema"))
            },
        ));

        let worker = ContextPlanPrecomputeWorker::new(
            Arc::clone(&l1),
            Arc::clone(&l2),
            source,
            Duration::from_millis(10),
        );
        let (handle, join) = worker.spawn();
        handle
            .notify(ContextPoolMutation::new(
                authorization(),
                "repo",
                "branch",
                ContextPoolMutationKind::Eviction,
            ))
            .await
            .expect("notify");

        let received = receiver.recv().await.expect("invalidation receive");
        assert_eq!(received.kind, ContextPoolMutationKind::Eviction);

        drop(handle);
        join.await.expect("worker join");
    }
}
