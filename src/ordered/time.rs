// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Time as the caller supplies it. The library never reads a clock.

use core::ops::Add;
use core::time::Duration;

/// A point in time, in microseconds since an origin the caller chooses.
/// Tests can run on virtual time.
///
/// The clock behind it MUST keep counting while the device sleeps
/// (`CLOCK_BOOTTIME` on Linux and Android, `mach_continuous_time` on Apple
/// platforms). `std::time::Instant` doesn't on those platforms. A clock that
/// stops would make a phone that slept for hours believe that seconds
/// passed, and keep sending on connections the server dropped long ago.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(u64);

impl Instant {
    pub const fn from_micros(micros: u64) -> Self {
        Self(micros)
    }

    pub const fn as_micros(self) -> u64 {
        self.0
    }

    /// Returns `None` when the deadline cannot be represented in microseconds.
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        let micros = u64::try_from(duration.as_micros()).ok()?;
        self.0.checked_add(micros).map(Self)
    }

    pub fn saturating_duration_since(self, earlier: Instant) -> Duration {
        Duration::from_micros(self.0.saturating_sub(earlier.0))
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, rhs: Duration) -> Instant {
        self.checked_add(rhs).unwrap_or(Instant(u64::MAX))
    }
}

/// Wall-clock time in seconds since the Unix epoch, used for restart
/// accounting and MLS credential lifetime checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WallTime(pub u64);
