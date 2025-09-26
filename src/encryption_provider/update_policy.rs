// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use chrono::{DateTime, Utc};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct CombinedUpdatePolicy {
    pub t_policy: UpdatePolicy,
    pub pq_policy: Option<UpdatePolicy>,
}

impl CombinedUpdatePolicy {
    pub fn pq_update_is_due(&self, now: DateTime<Utc>) -> bool {
        self.pq_policy
            .as_ref()
            .is_some_and(|p| p.update_is_due(now))
    }

    pub fn t_update_is_due(&self, now: DateTime<Utc>) -> bool {
        self.t_policy.update_is_due(now)
    }

    pub fn update_is_due(&self, now: DateTime<Utc>) -> bool {
        self.t_update_is_due(now) || self.pq_update_is_due(now)
    }

    pub fn reset_t(&mut self, now: DateTime<Utc>) {
        self.t_policy.reset(now);
    }

    pub fn reset_pq(&mut self, now: DateTime<Utc>) {
        // Since PQ update simply T update, we reset both
        self.t_policy.reset(now);
        if let Some(policy) = self.pq_policy.as_mut() {
            policy.reset(now);
        }
    }

    pub fn increment_bytes_transferred(&mut self, bytes: u64) {
        self.t_policy.increment_bytes_transferred(bytes);
        if let Some(policy) = self.pq_policy.as_mut() {
            policy.increment_bytes_transferred(bytes);
        }
    }
}

impl Default for CombinedUpdatePolicy {
    fn default() -> Self {
        let t_policy = UpdatePolicy {
            time_based: Some(TimeBasedUpdatePolicy::new(ONE_DAY)),
            traffic_based: Some(TrafficBasedUpdatePolicy::new(ONE_GB)),
        };
        let pq_policy = UpdatePolicy {
            time_based: Some(TimeBasedUpdatePolicy::new(ONE_WEEK)),
            traffic_based: Some(TrafficBasedUpdatePolicy::new(TWO_GB)),
        };
        Self {
            t_policy,
            pq_policy: Some(pq_policy),
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct UpdatePolicy {
    time_based: Option<TimeBasedUpdatePolicy>,
    traffic_based: Option<TrafficBasedUpdatePolicy>,
}

const ONE_DAY_SECONDS: u64 = 60 * 60 * 24;
const ONE_DAY: Duration = Duration::from_secs(ONE_DAY_SECONDS);
const ONE_WEEK: Duration = Duration::from_secs(ONE_DAY_SECONDS * 7);
const ONE_GB: u64 = 1024 * 1024 * 1024; // In bytes
const TWO_GB: u64 = ONE_GB * 2; // In bytes

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
    /// Creates a new `UpdatePolicy` with the given time-based and traffic-based update policies.
    ///
    /// In case the given policies are **not** `None`, but either the time-based policy threshold
    /// is under 1 second or the traffic-based policy threshold is 0, the policy will be ignored,
    /// respectively.
    pub fn new(
        time_based: Option<TimeBasedUpdatePolicy>,
        traffic_based: Option<TrafficBasedUpdatePolicy>,
    ) -> Self {
        Self {
            time_based: time_based.filter(|p| p.duration.as_secs() > 0),
            traffic_based: traffic_based.filter(|p| p.update_threshold > 0),
        }
    }

    pub fn time_based(&self) -> Option<&TimeBasedUpdatePolicy> {
        self.time_based.as_ref()
    }

    pub fn traffic_based(&self) -> Option<&TrafficBasedUpdatePolicy> {
        self.traffic_based.as_ref()
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

    pub fn duration(&self) -> Duration {
        self.duration
    }

    pub fn update_time(&self) -> DateTime<Utc> {
        self.last_update
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

    pub fn update_threshold(&self) -> u64 {
        self.update_threshold
    }

    pub fn bytes_transferred(&self) -> u64 {
        self.bytes_transferred
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
