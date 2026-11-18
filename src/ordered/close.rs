// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reasons and faults.

/// The local reason this side ended a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// The peer's credential was revoked.
    Revoked,
    /// A newer session of the same identity on the same binding replaced
    /// this one.
    Replaced,
    /// This side stops serving the session.
    Shutdown,
    /// The peer kept a leaf key longer than the rekey policy allows.
    PolicyViolation,
    /// The application rejected the peer during authorization.
    Rejected(u16),
    /// A code the application defines.
    Application(u16),
}

/// Why a connection was interrupted. The session survives, and the initiator
/// may reconnect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterruptCause {
    /// The ordered stream implementation is unavailable.
    Unavailable,
    /// The transport failed or ended without a `close_notify`, which may
    /// mean the last records were cut off.
    Transport,
    /// Nothing arrived for the idle timeout.
    IdleTimeout,
    /// A message that wasn't authenticated broke the rules. Anyone who can
    /// write to the connection can cause this.
    Unauthenticated(PeerFault),
    /// The peer sent `close_notify`: it sent nothing more.
    ClosedByPeer,
    /// This side closed the connection.
    ClosedLocally,
    /// The session moved to a newer connection (adoption). The engine
    /// deleted this connection's keys itself.
    Replaced,
    /// A key reached its AEAD usage limit before a new epoch was current.
    UsageLimit,
    /// A Commit was neither confirmed nor dropped in time.
    CommitUnconfirmed,
    /// The application didn't answer the authorization of a staged Commit
    /// in time. The Commit is discarded.
    AuthorizationTimeout,
    /// Neither a Challenge nor a Reset answered a Reconnect in time. The
    /// responder may have lost the session without keeping reset state.
    ReconnectUnanswered,
    /// No Adopted followed a ChallengeResponse in time.
    AdoptedMissing,
    /// A responder connection sent no complete first message in time.
    FirstMessageTimeout,
    /// The responder refused the connection because it already works on as
    /// many first messages as its limit allows.
    Overloaded,
    /// An authenticated message was invalid, and the session ends. The
    /// engine got that message, and every complete input before it, through
    /// the [`crate::ToEngine`] messages of the same read.
    Fatal(FatalFault),
}

/// What was wrong with a message from the peer's side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerFault {
    Unparseable,
    TooLarge,
    AuthenticationFailed,
    NotPermittedInState,
}

/// A session ended because of a message only the peer, or someone holding
/// the connection's keys, could have made. The session is deleted and not
/// reconnected (MLS-TLS "Errors").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatalFault {
    /// A Commit that fails a check of the profile or of MLS-TLS.
    InvalidCommit,
    /// An EpochKeyUpdate that fails a check of the profile.
    InvalidEpochKeyUpdate,
    /// An MLSMessage in a data record of an epoch that doesn't parse.
    MalformedMessage,
    /// An MLSMessage in a data record of an epoch that is neither a Commit
    /// nor an EpochKeyUpdate.
    UnexpectedMessage,
    /// The application rejected a staged Commit's new key or credential.
    CredentialRejected,
}
