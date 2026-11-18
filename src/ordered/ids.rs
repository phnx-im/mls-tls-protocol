// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identifiers.

/// Names a session locally. Stored with the session and stable
/// across restarts. Never sent on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub u64);

/// Names a connection locally, unique within one engine for its lifetime.
/// [`crate::Admission`] assigns handles too, from the same space. Never sent
/// on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionHandle(pub u64);

/// Names an authorization request until the application answers it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RequestId(pub u64);

/// Names a storage transaction until the application reports it durable or
/// failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TxnId(pub u64);
