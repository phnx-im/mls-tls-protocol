// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::cell::Cell;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;

use thiserror::Error;

use super::auth::{AuthorizationRequest, Decision, PeerCredential};
use super::close::{CloseReason, FatalFault, InterruptCause, PeerFault};
use super::config::{
    AppProtocol, Binding, ConfigError, EngineConfig, ServerProvisioning, SessionSuite, SignerSet,
};
use super::ids::{ConnectionHandle, RequestId, SessionId, TxnId};
use super::storage::{StoreWrite, StoredState};
use super::stream::StreamConnection;
use super::time::{Instant, WallTime};

/// The single owner of session, handshake, epoch, and reconnection state.
///
/// See the [architecture](crate#architecture) for the event loop and
/// message routing.
pub struct Engine {
    admission: Arc<Admission>,
    owner: PhantomData<Cell<()>>,
}

impl Engine {
    /// Creates an engine with no sessions for an empty store. The
    /// application holds an exclusive lock on the store for the engine's
    /// lifetime. See [durable storage](crate#durable-storage).
    pub fn new(config: EngineConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            admission: Arc::new(Admission { _private: () }),
            owner: PhantomData,
        })
    }

    /// An engine with the sessions the application stored.
    ///
    /// Every restored session starts interrupted. An interruption keeps the
    /// start stored in the engine record. One with no stored start began
    /// after the last last-alive write, and counts from that write. So a
    /// restart never extends a session's time bound. A record that can't
    /// be read is skipped and reported in [`Restored::dropped`], and the
    /// engine starts with the rest.
    ///
    /// Sessions whose deletion was still outstanding are deleted, excluded
    /// from restore. A replacement marker resumes deletion of the old
    /// session and creation of its reset state.
    ///
    /// A wall clock behind the last-alive time makes the time already spent
    /// unknowable. `on_clock_behind` says what to do. The likely cause is a
    /// machine that started before its clock was synchronized, so a server
    /// waits for time synchronization before it restores and answers
    /// [`ClockBehind::Refuse`].
    pub fn restore(
        _config: EngineConfig,
        stored: StoredState,
        _origin: RestoreOrigin,
        _on_clock_behind: ClockBehind,
        _wall_now: WallTime,
        _now: Instant,
    ) -> Result<Restored, RestoreError> {
        Err(RestoreError::Unavailable(stored))
    }

    // Initiator.

    /// Starts a new session as initiator. The suites and the pre-handshake
    /// come with the server's provisioning, since nothing is negotiated.
    /// Open the first connection with [`Engine::open_stream`]. Reconnects use the
    /// pre-handshake's session mode on their own.
    pub fn connect(
        &mut self,
        binding: Binding,
        server: &ServerProvisioning,
        _now: Instant,
    ) -> Result<SessionId, EngineError> {
        if binding == Binding::Datagram {
            return Err(EngineError::UnsupportedBinding);
        }
        let SessionSuite::Single(suite) = server.suite else {
            return Err(ConfigError::UnsupportedApq.into());
        };
        Err(EngineError::UnsupportedSuite(suite))
    }

    /// A new stream connection for an initiator's session: its first one, or
    /// a reconnection after an interruption. The application has opened the
    /// transport and decides when to call this, so backoff and reacting to
    /// network changes are its choice.
    pub fn open_stream(
        &mut self,
        _session: SessionId,
        _now: Instant,
    ) -> Result<StreamConnection, EngineError> {
        Err(EngineError::Unavailable)
    }

    // Responder.

    /// The responder's entry point on threads that accept connections.
    pub fn admission(&self) -> Arc<Admission> {
        Arc::clone(&self.admission)
    }

    // Input from connections and from the application.

    pub fn handle_from_connection(
        &mut self,
        _message: ToEngine,
        _now: Instant,
    ) -> Result<(), EngineError> {
        Err(EngineError::Unavailable)
    }

    /// A connection is gone: it reported [`crate::Interrupted`], or the
    /// application closed its transport ([`InterruptCause::Transport`]).
    pub fn connection_closed(
        &mut self,
        _connection: ConnectionHandle,
        _cause: InterruptCause,
        _now: Instant,
    ) -> Result<(), EngineError> {
        Err(EngineError::Unavailable)
    }

    pub fn authorize(
        &mut self,
        _request: RequestId,
        _decision: Decision,
        _now: Instant,
    ) -> Result<(), EngineError> {
        Err(EngineError::Unavailable)
    }

    /// A job's result. A result that is stale, because the session ended,
    /// reconnected, or moved on meanwhile, is discarded and its secrets are
    /// erased. A job that never returns is covered by the handshake and
    /// commit timeouts.
    pub fn job_done(&mut self, _result: JobResult, _now: Instant) -> Result<(), EngineError> {
        Err(EngineError::Unavailable)
    }

    /// The transaction is durable. Each transaction is acknowledged on its
    /// own, in any order across sessions.
    pub fn store_done(&mut self, _txn: TxnId, _now: Instant) -> Result<(), EngineError> {
        Err(EngineError::Unavailable)
    }

    /// The application gave up on a transaction. Retrying first is always
    /// safe, because live connections keep forwarding without the store.
    ///
    /// For a session's transaction the engine ends the session at once with
    /// [`SessionEnd::StorageFailed`] and retires its connections. The store
    /// may still hold the session's previous record, so the engine keeps
    /// the deletion as an obligation: it writes the session into the
    /// engine record as one to delete, and retries the deletion. Fatal
    /// errors and revocation take the same path. If the engine record
    /// can't be written either, the store is unusable: the application
    /// stops the engine and restores only from a repaired store.
    ///
    /// For the engine record the engine stops admitting new first messages
    /// until a later engine write succeeds.
    pub fn store_failed(&mut self, _txn: TxnId, _now: Instant) -> Result<(), EngineError> {
        Err(EngineError::Unavailable)
    }

    /// Ends a session and deletes its state, keeping reset state if the
    /// protocol keeps it. Its connection gets a `close_notify`, which tells
    /// the peer only that the connection closed. The peer learns that the
    /// session is gone from the Reset that answers its next Reconnect, once
    /// the deletion is durable. The reason stays local. Used for
    /// revocation and shutdown. An application that wants the peer to know
    /// why says so in its own protocol first.
    pub fn close_session(
        &mut self,
        _session: SessionId,
        _reason: CloseReason,
        _now: Instant,
    ) -> Result<(), EngineError> {
        Err(EngineError::Unavailable)
    }

    /// Asks for a Commit in the session as soon as the protocol allows.
    /// The application paces these itself, for example during a key
    /// rollover across thousands of sessions.
    pub fn request_commit(
        &mut self,
        _session: SessionId,
        _commit: CommitRequest,
        _now: Instant,
    ) -> Result<(), EngineError> {
        Err(EngineError::Unavailable)
    }

    /// Adds signing keys, for a rollover. With `for_new_sessions` they sign
    /// new sessions from now on. Existing sessions move to them with
    /// [`CommitRequest::NewCredential`].
    pub fn add_signer(
        &mut self,
        _signers: SignerSet,
        _for_new_sessions: bool,
    ) -> Result<(), EngineError> {
        Err(EngineError::Unavailable)
    }

    /// Removes a signing key once no session uses it.
    pub fn remove_signer(&mut self, _public_key: &[u8]) -> Result<(), EngineError> {
        Err(EngineError::Unavailable)
    }

    pub fn handle_timeout(
        &mut self,
        _now: Instant,
        _wall_now: WallTime,
    ) -> Result<(), EngineError> {
        Err(EngineError::Unavailable)
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        None
    }

    /// Call until `None` after every input.
    pub fn poll_output(&mut self) -> Option<Output> {
        None
    }

    /// The sessions the engine holds. After a restore the application
    /// checks each against its registry and closes those it no longer
    /// accepts.
    pub fn sessions(&self) -> impl Iterator<Item = SessionInfo> + '_ {
        std::iter::empty()
    }

    pub fn stats(&self) -> EngineStats {
        EngineStats::default()
    }
}

/// Where the stored state came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreOrigin {
    /// The store the engine last wrote to, with every acknowledged
    /// transaction in it.
    Latest,
    /// Possibly an earlier copy, such as a backup or a VM snapshot. A
    /// restored pending epoch may have been current in the lost copy, so
    /// the engine marks every restored epoch, current and pending, as one
    /// that accepts no early data, stores the marks, and admits nothing
    /// before they are durable. Early data comes back only in epochs
    /// created after this restore, also across later restores reported as
    /// `Latest`. For application protocols without early data there is
    /// nothing to mark. Sessions that moved on since the copy are lost, and
    /// their clients get no answer to a Reconnect.
    MayBeEarlierCopy,
}

/// What restore does when the wall clock is behind the last-alive time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockBehind {
    /// Fail with [`RestoreError::ClockBehind`], so the application can
    /// retry once the clock is synchronized.
    Refuse,
    /// Delete every interrupted session, since its bound may have passed.
    /// Every client of those sessions starts over.
    ExpireInterrupted,
}

pub enum RestoreError {
    Config(ConfigError),
    /// Returns the untouched caller-supplied records.
    Unavailable(StoredState),
    /// Hands the stored state back for a later attempt.
    ClockBehind {
        stored: StoredState,
        last_alive: WallTime,
    },
}

pub struct Restored {
    pub engine: Engine,
    pub dropped: Vec<DroppedRecord>,
}

pub struct DroppedRecord {
    pub session: SessionId,
    pub problem: RecordProblem,
}

#[derive(Clone, Copy, Debug)]
pub enum RecordProblem {
    /// Written by a newer version of the library, for example before a
    /// rollback.
    NewerVersion,
    Corrupt,
}

pub enum CommitRequest {
    /// Update this side's leaf according to the session's rekey policy.
    Update,
    /// Update this side's leaf in both APQ groups.
    FullUpdate,
    /// Update this side's leaf in the T group of an APQ session.
    PartialUpdate,
    /// Move this side to the credential of the signer with this public key.
    NewCredential(Vec<u8>),
}

pub enum Output {
    /// Route to the connection's owner, which passes it to `apply`. Messages
    /// for one connection must arrive in the order the engine emits them.
    ToConnection(ConnectionHandle, ToConnection),
    /// Write durably, then call [`Engine::store_done`] or
    /// [`Engine::store_failed`].
    Store(StoreWrite),
    /// Run anywhere, then hand the result to [`Engine::job_done`].
    Job(Job),
    Event(Box<Event>),
}

pub enum Event {
    /// Answer with [`Engine::authorize`]. The engine waits up to its
    /// authorization wait.
    Authorize(AuthorizationRequest),
    /// A new session is established. Comes once per session, when epoch 1
    /// is confirmed and, at the responder, stored.
    Established {
        session: SessionId,
        connection: ConnectionHandle,
        peer: PeerCredential,
    },
    /// An interrupted session continues on a new connection. Data sent on
    /// the old connection may be lost, and the application protocol
    /// resynchronizes.
    Resumed {
        session: SessionId,
        connection: ConnectionHandle,
        /// The responder accepted early data on this connection.
        early_data_accepted: bool,
    },
    EpochChanged {
        session: SessionId,
        epoch: u64,
    },
    /// The connection is gone and the session waits for a reconnection. An
    /// initiator opens a new connection when it chooses.
    Interrupted {
        session: SessionId,
        connection: ConnectionHandle,
        cause: InterruptCause,
    },
    /// The session is deleted.
    Closed {
        session: SessionId,
        reason: SessionEnd,
    },
    /// The engine is done with this connection. A stream connection can be
    /// dropped once `poll_transmit` has nothing left. Comes for every
    /// connection, also for candidates that were never adopted and for
    /// failed handshakes.
    ConnectionDone {
        connection: ConnectionHandle,
    },
    /// Input that broke the rules but could have come from anyone. For
    /// counting and rate limiting.
    Misbehavior {
        connection: ConnectionHandle,
        fault: PeerFault,
    },
}

#[derive(Clone, Copy, Debug)]
pub enum SessionEnd {
    /// Closed by this side.
    Local(CloseReason),
    /// Initiator: the responder answered a Reconnect with a Reset. It no
    /// longer holds the session. A Reset carries no reason.
    Reset,
    /// The session stayed interrupted for its whole time bound.
    TimeBound,
    /// Initiator: the initial key agreement didn't complete. Its connection
    /// was interrupted before the ServerHello arrived, or the time for it
    /// passed. A server that rejects a ClientHello closes the connection
    /// without an answer, so this is also how a rejection looks. Never
    /// final: the client backs off and tries again.
    HandshakeFailed(InterruptCause),
    /// Responder: epoch 1 wasn't confirmed in time. Nothing was stored.
    HandshakeExpired,
    /// A storage transaction for the session failed.
    StorageFailed,
    Fatal(FatalFault),
}

/// The local and remote socket addresses of a TCP connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Path {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

/// The responder's shared entry point for threads that accept TCP connections.
pub struct Admission {
    _private: (),
}

impl Admission {
    /// A connection for a TCP connection the application accepted. It
    /// doesn't involve the engine. The connection talks to the engine once
    /// its first message, a ClientStart or a ClientHello, is complete, and
    /// is interrupted with [`InterruptCause::FirstMessageTimeout`] if that
    /// takes too long. The engine answers a session-mode ClientStart itself
    /// and hands an hpke one to a [`Job`].
    ///
    /// The application caps the connections that haven't sent a complete
    /// first message, and when the cap is reached it closes the oldest such
    /// connection, not the new one. An attacker who opens idle connections
    /// then delays no client by more than the first-message timeout.
    pub fn accept_stream(
        &self,
        _path: Path,
        _now: Instant,
    ) -> Result<StreamConnection, EngineError> {
        Err(EngineError::Unavailable)
    }
}

/// From a connection to the engine. Opaque.
pub struct ToEngine {
    connection: ConnectionHandle,
}

impl ToEngine {
    pub fn connection(&self) -> ConnectionHandle {
        self.connection
    }
}

/// From the engine to a connection: profile messages to send, keys to
/// install or delete, a verdict on a candidate, a close. Opaque.
pub struct ToConnection {
    _private: (),
}

/// Expensive work the engine hands out. `Send`, holds what it needs.
pub struct Job {
    kind: JobKind,
    session: SessionId,
}

impl Job {
    /// So a pool can put the Commits of live sessions before a burst of new
    /// handshakes.
    pub fn kind(&self) -> JobKind {
        self.kind
    }

    pub fn session(&self) -> SessionId {
        self.session
    }

    /// `wall_now` is for the lifetimes of KeyPackages and LeafNodes, so a
    /// virtual clock reaches them too.
    pub fn run(self, _wall_now: WallTime) -> Result<JobResult, EngineError> {
        Err(EngineError::Unavailable)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobKind {
    /// Opening an hpke ClientStart: one decapsulation before the server
    /// knows whether the ClientStart is valid.
    PreHandshake,
    /// Processing a ClientHello or a ServerHello and Welcome.
    Handshake,
    /// Creating a Commit.
    CreateCommit,
    /// Processing a Commit from the peer.
    ProcessCommit,
}

pub struct JobResult {
    _private: (),
}

pub struct SessionInfo {
    pub session: SessionId,
    pub peer: PeerCredential,
    pub binding: Binding,
    pub app_protocol: AppProtocol,
    pub epoch: u64,
    pub connection: Option<ConnectionHandle>,
    pub established: WallTime,
    pub app_data: Vec<u8>,
    pub reauthorize_at: Option<WallTime>,
}

/// Gauges of the engine, for metrics.
#[derive(Clone, Copy, Debug, Default)]
pub struct EngineStats {
    pub sessions: u64,
    pub interrupted_sessions: u64,
    pub pending_handshakes: u64,
    pub jobs_out: u64,
    pub outputs_held_for_storage: u64,
    pub transactions_out: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EngineError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("ordered session handling is unavailable")]
    Unavailable,
    #[error("the requested binding is unsupported")]
    UnsupportedBinding,
    #[error("MLS suite {0:#06x} is unsupported")]
    UnsupportedSuite(u16),
    #[error("unknown session")]
    UnknownSession,
    #[error("the session uses a different binding")]
    WrongBinding,
    /// The session has a connection that isn't interrupted.
    #[error("the session already has a connection")]
    Connected,
    /// A session still uses the signing key.
    #[error("the signer is in use")]
    SignerInUse,
    /// The engine record couldn't be stored, see [`Engine::store_failed`].
    #[error("the store is unavailable")]
    StorageUnavailable,
    /// No pre-handshake configuration of the server is usable with the
    /// library's crypto backend.
    #[error("the pre-handshake configuration is unsupported")]
    UnsupportedPreHandshake,
}
