// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Authorization: the application decides who gets a session.
//!
//! The library authorizes nothing by itself. It asks when a session is
//! created, when a Commit changes the peer's signature key or credential,
//! and when a time the application set for the session passes.
//! Reconnections are not authorized: a session that the application doesn't
//! close lives on through Reconnects for as long as its time bound allows.
//! Revocation therefore means calling [`crate::Engine::close_session`], and
//! after every restore the application reconciles
//! [`crate::Engine::sessions`] with its registry.

use std::net::SocketAddr;

use super::close::CloseReason;
use super::config::{AppProtocol, Binding, SessionSuite};
use super::ids::{ConnectionHandle, RequestId, SessionId};
use super::time::WallTime;

/// One credential of the peer and the key it signs with.
///
/// The signature key has been verified against the KeyPackage or LeafNode.
/// The application binds that key to an identity through its authorization
/// policy. The claimed identity is unverified.
///
/// A KeyPackage can be replayed, so its signature doesn't show that the
/// peer on this connection holds the key. That holds once epoch 1 is
/// confirmed, and the engine stores and replaces nothing before.
#[derive(Clone, Debug)]
pub struct CredentialEvidence {
    pub signature_key: Vec<u8>,
    pub signature_scheme: u16,
    /// The identity the credential asserts. Unverified.
    pub claimed_identity: Vec<u8>,
    /// The complete MLS credential.
    pub credential: Vec<u8>,
}

/// The peer's credentials and the session's suites.
#[derive(Clone, Debug)]
pub struct PeerCredential {
    /// In the session's group, the T group with APQ.
    pub credential: CredentialEvidence,
    /// In the PQ group of an APQ session. The application accepts only if
    /// both credentials belong to the same identity in its registry.
    pub pq_credential: Option<CredentialEvidence>,
    /// Suite policy belongs to authorization, for example whether an
    /// identity that needs post-quantum signatures may hold a session in
    /// [`crate::ApqMode::Confidentiality`].
    pub suite: SessionSuite,
    pub app_protocol: AppProtocol,
}

#[derive(Clone, Copy, Debug)]
pub enum AuthorizationStage {
    /// A ClientHello (responder) or a ServerHello (initiator).
    NewSession,
    /// A Commit that changes the peer's signature key or its credential,
    /// in either group. A key rollover can change the key while the bytes
    /// of a basic credential stay the same. The Commit is staged until the
    /// answer and data keeps flowing. A rejection ends the session, because
    /// the staged Commit is authenticated and becomes invalid. No answer in
    /// time interrupts the connection and discards the Commit.
    KeyChange,
    /// The time from [`Decision::Accept::reauthorize_at`] passed. A
    /// rejection closes the session.
    Reauthorize,
}

#[derive(Clone, Debug)]
pub struct AuthorizationRequest {
    pub id: RequestId,
    pub stage: AuthorizationStage,
    pub session: SessionId,
    pub binding: Binding,
    /// The connection the request came in on, if there is one.
    pub connection: Option<ConnectionHandle>,
    /// The peer's address on that connection, for audit logs.
    pub remote: Option<SocketAddr>,
    pub peer: PeerCredential,
}

/// The answer to an [`AuthorizationRequest`]. The engine ignores an answer
/// that comes after its authorization wait, or a second answer.
#[derive(Clone, Debug)]
pub enum Decision {
    Accept {
        /// An older session of the same identity on the same binding to
        /// delete. It goes only once the new session's epoch 1 is
        /// confirmed, because a replayed ClientHello must not end a live
        /// session. The new session's first stored transaction names the
        /// old one, so a crash between the two writes still completes the
        /// replacement on restore (CONTRACT.md, "Storage").
        replaces: Option<SessionId>,
        /// Stored with the session and handed back in
        /// [`crate::SessionInfo`], for example a lease or a policy version.
        app_data: Vec<u8>,
        /// When to ask again with [`AuthorizationStage::Reauthorize`], for
        /// example when the peer's certificate expires.
        reauthorize_at: Option<WallTime>,
    },
    /// Nothing reaches the peer. A rejected ClientHello is closed without
    /// an answer (MLS-TLS "ClientStart and ServerStart"), and a rejected
    /// session ends with a closed connection. The reason is for the
    /// application's events and logs.
    Reject(CloseReason),
}
