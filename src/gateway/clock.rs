// Copyright (c) Verdictan.com
// SPDX-License-Identifier: BUSL-1.1

use chrono::{DateTime, Utc};

/// Shared gateway clock abstraction for time-sensitive runtime paths.
pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;

    fn unix_seconds(&self) -> u64 {
        self.now().timestamp().max(0) as u64
    }

    fn unix_micros(&self) -> u128 {
        self.now().timestamp_micros().max(0) as u128
    }
}

#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}
