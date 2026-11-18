// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable session state.
//!
//! The engine describes every change to stored state as a [`StoreWrite`]
//! and holds back each output that depends on it until the application
//! reports the write durable with [`crate::Engine::store_done`]. A crash
//! therefore never leaves the peer ahead of what is stored. CONTRACT.md
//! lists every write and the output it gates.
//!
//! The library owns the format of the records, versions it, and rejects the
//! state of today's library. The application stores them as opaque bytes.
//! What a store has to guarantee is in CONTRACT.md ("Storage"): atomic
//! transactions, a real flush, encryption at rest, no backups, one engine
//! per store.

use zeroize::Zeroize;

use super::ids::{SessionId, TxnId};
use super::time::WallTime;

/// The state of a session's epochs: the group state of the current and the
/// pending epoch (both groups with APQ), the current epoch's init_secret,
/// the values the profile derives per epoch as far as they aren't deleted
/// yet. Large, tens of kilobytes with PQ keys. Changes when an epoch does.
/// Contains secrets and is zeroized on drop.
pub struct EpochRecord {
    bytes: Vec<u8>,
}

/// The small part of a session that changes more often: the initiator's
/// Reconnect number, deadlines, the application's data and next
/// authorization time. For an application protocol with early data also
/// the responder's latest fresh Reconnect, and which restored epochs may
/// not accept early data. In a session that replaced another one, the old
/// session's id: the old session's deletion is a transaction of its own,
/// and restore completes it if a crash came between the two. Contains no
/// key.
pub struct CounterRecord {
    bytes: Vec<u8>,
}

/// What a responder keeps of a deleted session to answer a Reconnect with a
/// Reset: the references, `reset_key` and `channel_key` of the current and
/// pending epoch, and the suite. No data secret, no group state.
pub struct ResetRecord {
    bytes: Vec<u8>,
}

/// State of the engine as a whole: the wall time it was last known alive,
/// the start of every interruption, and the sessions whose deletion is
/// still outstanding after a failed write.
pub struct EngineRecord {
    bytes: Vec<u8>,
}

macro_rules! opaque_record {
    ($($t:ty),*) => {$(
        impl $t {
            pub fn from_bytes(bytes: Vec<u8>) -> Self {
                Self { bytes }
            }

            pub fn as_bytes(&self) -> &[u8] {
                &self.bytes
            }
        }
    )*};
}

opaque_record!(EpochRecord, CounterRecord, ResetRecord, EngineRecord);

impl Drop for EpochRecord {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for ResetRecord {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

pub enum StoreOp {
    PutEpochs(EpochRecord),
    PutCounters(CounterRecord),
    /// Deletes the session's records. Comes with a `PutReset` when the
    /// responder keeps reset state.
    DeleteSession,
    PutReset {
        record: ResetRecord,
        expires: WallTime,
    },
    DeleteReset,
}

/// One transaction. Its operations apply atomically.
///
/// Transactions of one session apply in the order of their ids.
/// Transactions of different sessions are independent, so a store may keep
/// one file or one key per session and acknowledge each as it finishes. No
/// transaction spans two sessions.
pub enum StoreWrite {
    Session {
        txn: TxnId,
        session: SessionId,
        ops: Vec<StoreOp>,
    },
    Engine {
        txn: TxnId,
        record: EngineRecord,
    },
}

impl StoreWrite {
    pub fn txn(&self) -> TxnId {
        match self {
            StoreWrite::Session { txn, .. } | StoreWrite::Engine { txn, .. } => *txn,
        }
    }
}

/// One stored session, handed back at startup.
pub struct StoredSession {
    pub session: SessionId,
    pub epochs: EpochRecord,
    pub counters: CounterRecord,
}

/// Everything the application stored.
#[derive(Default)]
pub struct StoredState {
    pub engine: Option<EngineRecord>,
    pub sessions: Vec<StoredSession>,
    pub resets: Vec<(SessionId, ResetRecord, WallTime)>,
}
