// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use thiserror::Error;

use super::config::Binding;
use super::engine::EngineError;
use super::wire::{HEADER_LEN, MAX_PLAINTEXT};

pub(super) const TAG_LEN: usize = 16;

/// A payload in a caller-owned buffer, with room for record overhead.
pub struct PacketBuf<'a> {
    buf: &'a mut [u8],
    start: usize,
    end: usize,
}

impl<'a> PacketBuf<'a> {
    /// Takes the payload in `buf[start..end]`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPayloadRange`] if the range is outside the buffer or reversed.
    pub fn new(buf: &'a mut [u8], start: usize, end: usize) -> Result<Self, InvalidPayloadRange> {
        if start > end || end > buf.len() {
            return Err(InvalidPayloadRange);
        }

        Ok(Self { buf, start, end })
    }

    /// The current span of the buffer.
    pub fn bytes(&self) -> &[u8] {
        &self.buf[self.start..self.end]
    }

    pub fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.start..self.end]
    }

    pub fn headroom(&self) -> usize {
        self.start
    }

    pub fn tailroom(&self) -> usize {
        self.buf.len() - self.end
    }

    pub(super) fn frame_mut(&mut self, before: usize, after: usize) -> Option<&mut [u8]> {
        let start = self.start.checked_sub(before)?;
        let end = self.end.checked_add(after)?;
        self.buf.get_mut(start..end)
    }

    pub(super) fn include_frame(&mut self, before: usize, after: usize) {
        self.start -= before;
        self.end += after;
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("payload range is outside the packet buffer or reversed")]
pub struct InvalidPayloadRange;

/// Room for record framing, authentication, and padding around a payload.
#[derive(Clone, Copy, Debug)]
pub struct Overhead {
    pub headroom: usize,
    pub tailroom: usize,
}

impl Overhead {
    /// The maximum room required by the binding, including maximum padding.
    pub fn max(binding: Binding) -> Result<Self, EngineError> {
        match binding {
            Binding::Stream => Ok(Self {
                headroom: HEADER_LEN,
                tailroom: MAX_PLAINTEXT + TAG_LEN,
            }),
            Binding::Datagram => Err(EngineError::UnsupportedBinding),
        }
    }
}
