// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use thiserror::Error;

pub(crate) mod component;
#[cfg(fuzzing)]
mod fuzz;
pub(crate) mod handshake;
pub(crate) mod pre_handshake;
pub(crate) mod profile;
#[cfg(test)]
mod tests;
#[cfg(fuzzing)]
pub use fuzz::fuzz_wire;

pub(crate) const PROFILE_COMPONENT: u16 = 0x8000;
pub(crate) const MLS_TLS_COMPONENT: u16 = 0x8001;
pub(crate) const SUPPORTED_WIRE_FORMATS: u16 = 0xf000;
pub(crate) const REQUIRED_WIRE_FORMATS: u16 = 0xf001;
pub(crate) const TWO_PARTY_WIRE_FORMAT: u16 = 0xf002;
pub(crate) const MLS_VERSION: u16 = 1;

pub(crate) const HEADER_LEN: usize = 5;
pub(crate) const MAX_PLAINTEXT: usize = 1 << 14;
pub(crate) const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 256;
pub(crate) const LEGACY_VERSION: [u8; 2] = [3, 3];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OuterType {
    Handshake = 22,
    Data = 23,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ContentType {
    Alert = 21,
    Handshake = 22,
    Data = 23,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum WireError {
    #[error("incomplete input")]
    Truncated,
    #[error("content exceeds its size limit")]
    TooLong,
    #[error("unsupported record or MLS version")]
    Version,
    #[error("unexpected content or message type")]
    Type,
    #[error("invalid value or encoding")]
    Invalid,
    #[error("unexpected trailing bytes")]
    Trailing,
    #[error("interrupted handshake fragment")]
    Fragment,
    #[error("a key switch must end its record")]
    KeySwitch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecordHeader {
    pub(crate) kind: OuterType,
    pub(crate) len: usize,
}

impl RecordHeader {
    pub(crate) fn decode(header: &[u8], protected_handshake: bool) -> Result<Self, WireError> {
        let [kind, major, minor, high, low] = *header.first_chunk().ok_or(WireError::Truncated)?;
        if [major, minor] != LEGACY_VERSION {
            return Err(WireError::Version);
        }
        let kind = match kind {
            22 => OuterType::Handshake,
            23 => OuterType::Data,
            _ => return Err(WireError::Type),
        };
        let len = usize::from(u16::from_be_bytes([high, low]));
        let max = match kind {
            OuterType::Handshake if !protected_handshake => MAX_PLAINTEXT,
            OuterType::Handshake | OuterType::Data => MAX_CIPHERTEXT,
        };
        if len == 0 {
            return Err(WireError::Invalid);
        }
        if len > max {
            return Err(WireError::TooLong);
        }
        Ok(Self { kind, len })
    }

    pub(crate) fn encode(self) -> Result<[u8; HEADER_LEN], WireError> {
        let [high, low] = u16::try_from(self.len)
            .map_err(|_| WireError::TooLong)?
            .to_be_bytes();
        Ok([
            self.kind as u8,
            LEGACY_VERSION[0],
            LEGACY_VERSION[1],
            high,
            low,
        ])
    }
}

impl ContentType {
    pub(crate) fn allowed(self, kind: OuterType) -> bool {
        match self {
            Self::Alert | Self::Handshake => true,
            Self::Data => kind == OuterType::Data,
        }
    }
}

pub(crate) fn inner_plaintext(
    kind: OuterType,
    input: &[u8],
) -> Result<(ContentType, usize), WireError> {
    if input.len() > protected_plaintext_limit(kind) {
        return Err(WireError::TooLong);
    }
    let end = input
        .iter()
        .rposition(|&byte| byte != 0)
        .ok_or(WireError::Type)?;
    let content = match input[end] {
        21 => ContentType::Alert,
        22 => ContentType::Handshake,
        23 => ContentType::Data,
        _ => return Err(WireError::Type),
    };
    if !content.allowed(kind) {
        return Err(WireError::Type);
    }
    validate_content(content, &input[..end])?;
    Ok((content, end))
}

pub(crate) fn validate_content(kind: ContentType, input: &[u8]) -> Result<(), WireError> {
    match kind {
        // RFC 8446 requires receivers to ignore the legacy alert level.
        ContentType::Alert if !matches!(input, [_, 0]) => Err(WireError::Invalid),
        ContentType::Handshake if input.is_empty() => Err(WireError::Invalid),
        ContentType::Alert | ContentType::Handshake | ContentType::Data => Ok(()),
    }
}

pub(crate) const fn protected_plaintext_limit(kind: OuterType) -> usize {
    match kind {
        OuterType::Handshake => MAX_PLAINTEXT + 1,
        OuterType::Data => MAX_PLAINTEXT,
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self(input)
    }

    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8], WireError> {
        let (value, remaining) = self.0.split_at_checked(len).ok_or(WireError::Truncated)?;
        self.0 = remaining;
        Ok(value)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<&'a [u8; N], WireError> {
        self.take(N)?.try_into().map_err(|_| WireError::Truncated)
    }

    pub(crate) fn byte(&mut self) -> Result<u8, WireError> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(*self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_be_bytes(*self.array()?))
    }

    pub(crate) fn vector(&mut self) -> Result<&'a [u8], WireError> {
        let first = self.byte()?;
        let high = usize::from(first & 0x3f);
        let len = match first >> 6 {
            0 => high,
            1 => {
                let len = (high << 8) | usize::from(self.byte()?);
                if len < 1 << 6 {
                    return Err(WireError::Invalid);
                }
                len
            }
            2 => {
                let [b, c, d] = *self.array()?;
                let len =
                    (high << 24) | (usize::from(b) << 16) | (usize::from(c) << 8) | usize::from(d);
                if len < 1 << 14 {
                    return Err(WireError::Invalid);
                }
                len
            }
            _ => return Err(WireError::Invalid),
        };
        self.take(len)
    }

    pub(crate) fn optional_vector(&mut self) -> Result<Option<&'a [u8]>, WireError> {
        match self.byte()? {
            0 => Ok(None),
            1 => self.vector().map(Some),
            _ => Err(WireError::Invalid),
        }
    }

    pub(crate) fn remaining(self) -> &'a [u8] {
        self.0
    }

    pub(crate) fn finish(self) -> Result<(), WireError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(WireError::Trailing)
        }
    }
}

pub(crate) fn put_length(len: usize, out: &mut Vec<u8>) -> Result<(), WireError> {
    match len {
        0..=0x3f => out.push(len as u8),
        0x40..=0x3fff => out.extend_from_slice(&(0x4000 | len as u16).to_be_bytes()),
        0x4000..=0x3fff_ffff => out.extend_from_slice(&(0x8000_0000 | len as u32).to_be_bytes()),
        _ => return Err(WireError::TooLong),
    }
    Ok(())
}

pub(crate) fn put_vector(input: &[u8], out: &mut Vec<u8>) -> Result<(), WireError> {
    put_length(input.len(), out)?;
    out.extend_from_slice(input);
    Ok(())
}

pub(crate) fn put_optional(input: Option<&[u8]>, out: &mut Vec<u8>) -> Result<(), WireError> {
    match input {
        Some(input) => {
            out.push(1);
            put_vector(input, out)
        }
        None => {
            out.push(0);
            Ok(())
        }
    }
}
