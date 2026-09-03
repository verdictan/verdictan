// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::{net::SocketAddr, thread};

use axum::Router;
use tokio::{net::TcpListener, sync::oneshot};

use super::deterministic_net::test_listener;

/// A spawned test server with lifecycle management.
pub(crate) struct SpawnedServer {
    pub addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join_handle: Option<thread::JoinHandle<()>>,
}

impl SpawnedServer {
    pub async fn start(listener: TcpListener, app: Router) -> Self {
        let addr = listener.local_addr().expect("local addr");
        let std_listener = listener.into_std().expect("listener into std");
        std_listener
            .set_nonblocking(true)
            .expect("listener nonblocking");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let join_handle = thread::Builder::new()
            .name("spawned-test-server".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("server runtime");
                runtime.block_on(async move {
                    let listener = TcpListener::from_std(std_listener).expect("listener from std");
                    let shutdown = async {
                        let _ = shutdown_rx.await;
                    };
                    axum::serve(listener, app)
                        .with_graceful_shutdown(shutdown)
                        .await
                        .ok();
                });
            })
            .expect("spawn server thread");
        Self {
            addr,
            shutdown_tx: Some(shutdown_tx),
            join_handle: Some(join_handle),
        }
    }

    pub async fn bind(app: Router) -> Self {
        Self::start_deterministic(app).await
    }

    async fn start_deterministic(app: Router) -> Self {
        let listener = test_listener().bind().await;
        Self::start(listener, app).await
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl Drop for SpawnedServer {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
        if let Some(join_handle) = self.join_handle.take() {
            let _ = join_handle.join();
        }
    }
}
