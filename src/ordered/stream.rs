// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::cell::Cell;
use std::marker::PhantomData;
use std::ops::Range;

use thiserror::Error;

use super::buf::{Overhead, PacketBuf};
use super::close::InterruptCause;
use super::engine::{EngineError, ToConnection, ToEngine};
use super::ids::ConnectionHandle;
use super::time::Instant;

/// One ordered TCP connection, driven by one mutable owner.
///
/// See [TCP record ordering](crate#tcp-record-ordering) for the caller's
/// obligations when routing engine messages and writing records.
pub struct StreamConnection {
    handle: ConnectionHandle,
    owner: PhantomData<Cell<()>>,
}

impl StreamConnection {
    pub fn handle(&self) -> ConnectionHandle {
        self.handle
    }

    /// 5 bytes of record header before the payload, the inner content type
    /// and the AEAD tag after it, plus padding. 22 bytes with a 16-byte tag
    /// and no padding.
    pub fn overhead(&self) -> Result<Overhead, EngineError> {
        Err(EngineError::Unavailable)
    }

    /// The largest payload [`StreamConnection::seal`] accepts, after subtracting the inner content type and padding.
    pub fn max_payload(&self) -> Result<usize, EngineError> {
        Err(EngineError::Unavailable)
    }

    /// Opens the complete records at the start of `input`, in place, and
    /// tells `sink` where their content is. Returns how far it got. The
    /// caller handles what the sink got before it moves the bytes after
    /// that to the front, and calls again with more.
    ///
    /// Reading pauses after a message whose effect on the records behind it
    /// depends on the engine: at the responder a ClientStart or a ClientHello
    /// (the keys of what follows) and a ChallengeResponse (adoption), at
    /// either side an EpochKeyUpdate whose epoch the connection has no keys
    /// for yet. Route the [`ToEngine`] the sink got and apply what comes
    /// back. [`StreamConnection::apply`] says when reading can continue.
    ///
    /// Every complete authenticated input reaches the sink before an error
    /// from a later record of the same call, so an invalid message earlier
    /// in the stream still ends the session.
    pub fn read(
        &mut self,
        _input: &mut [u8],
        _now: Instant,
        _sink: &mut impl Deliver,
    ) -> Result<ReadProgress, Interrupted> {
        Err(Interrupted {
            cause: InterruptCause::Unavailable,
        })
    }

    /// Seals application data into one data record in place. The record has
    /// to be written, before anything sealed or produced later. Call
    /// [`StreamConnection::poll_to_engine`] afterwards.
    pub fn seal(&mut self, _data: &mut PacketBuf<'_>, _now: Instant) -> Result<(), SealError> {
        Err(SealError::NotReady)
    }

    /// What the connection has for the engine outside of `read`: that a
    /// send key nears its usage limit, once per key. The engine then starts
    /// a Commit if it has none pending (MLS-TLS "Commits and Key Usage
    /// Limits"). A connection that only sends learns this only here. Call
    /// after `seal` and `poll_transmit` until `None`.
    pub fn poll_to_engine(&mut self) -> Option<ToEngine> {
        None
    }

    /// Applies a message from the engine and appends what it sends to `out`.
    /// For an epoch change that is the EpochKeyUpdate, and the next record
    /// sealed uses the new keys. Returns [`Applied::Resume`] when a paused
    /// read can continue. The caller then calls `read` again at once with
    /// the bytes it kept, without waiting for the socket.
    pub fn apply(
        &mut self,
        _message: ToConnection,
        _out: &mut Vec<u8>,
        _now: Instant,
    ) -> Result<Applied, Interrupted> {
        Err(Interrupted {
            cause: InterruptCause::Unavailable,
        })
    }

    /// Appends keepalives and other records the connection sends on its own.
    pub fn poll_transmit(&mut self, _out: &mut Vec<u8>, _now: Instant) -> Result<(), Interrupted> {
        Err(Interrupted {
            cause: InterruptCause::Unavailable,
        })
    }

    pub fn handle_timeout(&mut self, _now: Instant) -> Result<(), Interrupted> {
        Err(Interrupted {
            cause: InterruptCause::Unavailable,
        })
    }

    /// Changes only through calls on this connection.
    pub fn next_deadline(&self) -> Option<Instant> {
        None
    }

    /// Appends a protected `close_notify` if the connection has a key for
    /// it. The session stays: closing a connection doesn't end it.
    pub fn close(&mut self, _out: &mut Vec<u8>) -> Result<(), Interrupted> {
        Err(Interrupted {
            cause: InterruptCause::Unavailable,
        })
    }

    pub fn stats(&self) -> ConnectionStats {
        ConnectionStats::default()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
    Done,
    /// A paused read can continue.
    Resume,
}

/// Counters of one connection, for metrics.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConnectionStats {
    pub records_sent: u64,
    pub bytes_sent: u64,
    pub records_received: u64,
    pub bytes_received: u64,
    pub keepalives_received: u64,
    pub authentication_failures: u64,
}

#[derive(Clone, Copy, Debug)]
pub enum ReadProgress {
    /// Consumed this many bytes and needs more input.
    Consumed(usize),
    /// Consumed this many bytes and waits for an engine message.
    Paused(usize),
}

/// Receives what a connection opened. Data is opened in place: the caller
/// finds each record's content in the buffer it passed, at the range given,
/// once the call that opened it returns. So it can collect packets for a
/// batched TUN write without copying.
pub trait Deliver {
    /// The content of one data record at `at`. `early` marks early data,
    /// which may arrive late or twice. Keepalives aren't delivered.
    fn data(&mut self, at: Range<usize>, early: bool);
    /// Route to the engine.
    fn to_engine(&mut self, message: ToEngine);
}

/// The connection is unusable. Tell the engine with
/// [`crate::Engine::connection_closed`] and close the transport.
#[derive(Debug, Error)]
#[error("connection interrupted: {cause:?}")]
pub struct Interrupted {
    pub cause: InterruptCause,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SealError {
    /// The payload is larger than the connection allows.
    #[error("payload exceeds {max_payload} bytes")]
    TooLarge { max_payload: usize },
    /// Not enough room around the payload.
    #[error("insufficient room for the record overhead")]
    NoRoom,
    /// No send keys yet, or the connection is closing or interrupted.
    #[error("the connection is not ready to seal")]
    NotReady,
    /// The send key's reserve for a Commit, an EpochKeyUpdate, and a
    /// closing alert is in use. No data until the next epoch is current.
    #[error("the send key is reserved for control records")]
    ReserveInUse,
}
