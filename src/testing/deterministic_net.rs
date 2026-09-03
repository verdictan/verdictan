// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use std::sync::OnceLock;

use tokio::net::TcpListener;

static BINARY_LISTENER: OnceLock<DeterministicListener> = OnceLock::new();

/// Shared test listener helper that always binds loopback via the OS.
pub(crate) struct DeterministicListener;

impl DeterministicListener {
    pub fn new(_base_port: u16) -> Self {
        Self
    }

    pub fn from_binary() -> Self {
        Self::new(0)
    }

    pub async fn bind(&self) -> TcpListener {
        TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener")
    }
}

/// Process-scoped listener for unit tests in `cli/src/**`.
pub(crate) fn test_listener() -> &'static DeterministicListener {
    BINARY_LISTENER.get_or_init(DeterministicListener::from_binary)
}
