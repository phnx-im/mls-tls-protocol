// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use chrono::{DateTime, Utc};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct UpdatePolicy {
    time_based: Option<TimeBasedUpdatePolicy>,
    traffic_based: Option<TrafficBasedUpdatePolicy>,
}

impl From<TimeBasedUpdatePolicy> for UpdatePolicy {
    fn from(policy: TimeBasedUpdatePolicy) -> Self {
        UpdatePolicy {
            time_based: Some(policy),
            traffic_based: None,
        }
    }
}

impl From<TrafficBasedUpdatePolicy> for UpdatePolicy {
    fn from(policy: TrafficBasedUpdatePolicy) -> Self {
        UpdatePolicy {
            time_based: None,
            traffic_based: Some(policy),
        }
    }
}

impl UpdatePolicy {
    pub fn new(
        time_based: Option<TimeBasedUpdatePolicy>,
        traffic_based: Option<TrafficBasedUpdatePolicy>,
    ) -> Self {
        UpdatePolicy {
            time_based,
            traffic_based,
        }
    }

    pub fn update_is_due(&self, now: DateTime<Utc>) -> bool {
        let time_based_is_due = self
            .time_based
            .as_ref()
            .is_some_and(|policy| policy.update_is_due(now));
        let traffic_based_is_due = self
            .traffic_based
            .as_ref()
            .is_some_and(|policy| policy.update_is_due());

        time_based_is_due || traffic_based_is_due
    }

    pub fn reset(&mut self, now: DateTime<Utc>) {
        if let Some(policy) = self.time_based.as_mut() {
            policy.set_update_time(now);
        }
        if let Some(policy) = self.traffic_based.as_mut() {
            policy.reset();
        }
    }

    pub fn increment_bytes_transferred(&mut self, bytes: u64) {
        if let Some(policy) = &mut self.traffic_based {
            policy.increment_bytes_transferred(bytes);
        }
    }
}

#[derive(Clone, Debug)]
pub struct TimeBasedUpdatePolicy {
    duration: Duration,
    last_update: DateTime<Utc>,
}

impl TimeBasedUpdatePolicy {
    pub fn new(duration: std::time::Duration) -> Self {
        TimeBasedUpdatePolicy {
            duration,
            last_update: Utc::now(),
        }
    }

    pub fn update_is_due(&self, now: DateTime<Utc>) -> bool {
        if now >= self.last_update + self.duration {
            tracing::info!(time_since_last_update = ?now - self.last_update,
                "Update is due"
            );
            true
        } else {
            false
        }
    }

    pub fn set_update_time(&mut self, now: DateTime<Utc>) {
        self.last_update = now;
    }
}

#[derive(Clone, Debug)]
pub struct TrafficBasedUpdatePolicy {
    update_threshold: u64,
    bytes_transferred: u64,
}

impl TrafficBasedUpdatePolicy {
    pub fn new(update_threshold: u64) -> Self {
        TrafficBasedUpdatePolicy {
            update_threshold,
            bytes_transferred: 0,
        }
    }

    pub fn update_is_due(&self) -> bool {
        if self.bytes_transferred >= self.update_threshold {
            tracing::info!(bytes_transferred = self.bytes_transferred, "Update is due");
            true
        } else {
            false
        }
    }

    pub fn increment_bytes_transferred(&mut self, bytes: u64) {
        self.bytes_transferred += bytes;
    }

    pub fn reset(&mut self) {
        self.bytes_transferred = 0;
    }
}
