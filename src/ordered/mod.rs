// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

#![forbid(unsafe_code)]
#![deny(
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]

mod auth;
mod buf;
mod close;
mod config;
mod engine;
mod ids;
#[expect(
    dead_code,
    reason = "wired into connection state when the engine establishes sessions"
)]
mod record;
mod storage;
mod stream;
mod time;
#[expect(
    dead_code,
    reason = "wired into the engine and connections as their protocol states land"
)]
mod wire;

#[cfg(fuzzing)]
pub use wire::fuzz_wire;

pub use auth::{
    AuthorizationRequest, AuthorizationStage, CredentialEvidence, Decision, PeerCredential,
};
pub use buf::{InvalidPayloadRange, Overhead, PacketBuf};
pub use close::{CloseReason, FatalFault, InterruptCause, PeerFault};
pub use config::{
    AppProtocol, AppProtocolProfile, ApqMode, Binding, ClientPreHandshake, ConfigError, EarlyData,
    EarlyLimit, EngineConfig, Limits, Liveness, LocalTimeouts, PaddingPolicy, ProtocolTimes,
    RekeyPolicy, Secret, ServerPreHandshake, ServerPreHandshakeConfig, ServerProvisioning,
    SessionSuite, SignError, Signer, SignerSet,
};
pub use engine::{
    Admission, ClockBehind, CommitRequest, DroppedRecord, Engine, EngineError, EngineStats, Event,
    Job, JobKind, JobResult, Output, Path, RecordProblem, RestoreError, RestoreOrigin, Restored,
    SessionEnd, SessionInfo, ToConnection, ToEngine,
};
pub use ids::{ConnectionHandle, RequestId, SessionId, TxnId};
pub use storage::{
    CounterRecord, EngineRecord, EpochRecord, ResetRecord, StoreOp, StoreWrite, StoredSession,
    StoredState,
};
pub use stream::{
    Applied, ConnectionStats, Deliver, Interrupted, ReadProgress, SealError, StreamConnection,
};
pub use time::{Instant, WallTime};
