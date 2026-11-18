// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use mls_tls_protocol::{
    Engine, EngineError, EngineRecord, Instant, Output, ResetRecord, SessionId, StoreOp,
    StoreWrite, StoredSession, StoredState, TxnId, WallTime,
};

pub struct Pair {
    pub initiator: Endpoint,
    pub responder: Endpoint,
    pub now: Instant,
    pub wall_now: WallTime,
}

impl Pair {
    pub fn advance(&mut self, elapsed: Duration) {
        let previous_seconds = self.now.as_micros() / 1_000_000;
        self.now = self.now + elapsed;
        let elapsed_seconds = self.now.as_micros() / 1_000_000 - previous_seconds;
        self.wall_now = WallTime(self.wall_now.0.saturating_add(elapsed_seconds));
    }
}

pub struct Endpoint {
    pub engine: Engine,
    pub store: TestStore,
}

impl Endpoint {
    pub fn new(engine: Engine) -> Self {
        Self {
            engine,
            store: TestStore::default(),
        }
    }

    /// Drives the engine without automatically acknowledging storage writes.
    pub fn tick(
        &mut self,
        now: Instant,
        wall_now: WallTime,
    ) -> (Result<(), EngineError>, Vec<Output>) {
        let result = self.engine.handle_timeout(now, wall_now);
        let mut outputs = Vec::new();
        while let Some(output) = self.engine.poll_output() {
            match output {
                Output::Store(write) => self.store.stage(write),
                other => outputs.push(other),
            }
        }
        (result, outputs)
    }
}

#[derive(Default)]
pub struct TestStore {
    pending: VecDeque<StoreWrite>,
    engine: Option<EngineRecord>,
    sessions: BTreeMap<SessionId, StoredSession>,
    resets: BTreeMap<SessionId, (ResetRecord, WallTime)>,
}

impl TestStore {
    pub fn stage(&mut self, write: StoreWrite) {
        self.pending.push_back(write);
    }

    /// Returns the acknowledgement after applying one complete transaction.
    pub fn commit_next(&mut self) -> Option<TxnId> {
        let write = self.pending.pop_front()?;
        let txn = write.txn();
        match write {
            StoreWrite::Engine { txn: _, record } => {
                self.engine = Some(record);
            }
            StoreWrite::Session {
                txn: _,
                session,
                ops,
            } => {
                self.apply_session(session, ops);
            }
        }
        Some(txn)
    }

    pub fn fail_next(&mut self) -> Option<TxnId> {
        self.pending.pop_front().map(|write| write.txn())
    }

    /// A restart can read only completed transactions.
    pub fn crash(self) -> StoredState {
        StoredState {
            engine: self.engine,
            sessions: self.sessions.into_values().collect(),
            resets: self
                .resets
                .into_iter()
                .map(|(id, (reset, expires))| (id, reset, expires))
                .collect(),
        }
    }

    fn apply_session(&mut self, session: SessionId, ops: Vec<StoreOp>) {
        let current = self.sessions.remove(&session);
        let (mut epochs, mut counters) = current.map_or((None, None), |record| {
            (Some(record.epochs), Some(record.counters))
        });

        for op in ops {
            match op {
                StoreOp::PutEpochs(record) => epochs = Some(record),
                StoreOp::PutCounters(record) => counters = Some(record),
                StoreOp::DeleteSession => (epochs, counters) = (None, None),
                StoreOp::PutReset { record, expires } => {
                    self.resets.insert(session, (record, expires));
                }
                StoreOp::DeleteReset => {
                    self.resets.remove(&session);
                }
            }
        }

        match (epochs, counters) {
            (Some(epochs), Some(counters)) => {
                self.sessions.insert(
                    session,
                    StoredSession {
                        session,
                        epochs,
                        counters,
                    },
                );
            }
            (None, None) => {}
            (Some(_), None) | (None, Some(_)) => {
                panic!("session transaction has incomplete records")
            }
        }
    }
}
