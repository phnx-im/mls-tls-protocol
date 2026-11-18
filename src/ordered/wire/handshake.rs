// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use zeroize::Zeroizing;

use super::profile::{is_epoch_key_update, MAX_MLS_MESSAGE_LEN};
use super::{
    validate_content, ContentType, OuterType, RecordHeader, WireError,
    HEADER_LEN as RECORD_HEADER_LEN, MAX_PLAINTEXT,
};

const HEADER_LEN: usize = 4;
pub(crate) const MAX_CLIENT_START_LEN: usize = MAX_MLS_MESSAGE_LEN + (1 << 12);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HandshakeType {
    ClientStart = 1,
    ServerStart = 2,
    MlsMessage = 3,
    EndOfEarlyData = 5,
}

impl HandshakeType {
    fn read(header: &[u8; HEADER_LEN]) -> Result<(Self, usize), WireError> {
        let [kind, high, middle, low] = *header;
        let kind = match kind {
            1 => Self::ClientStart,
            2 => Self::ServerStart,
            3 => Self::MlsMessage,
            5 => Self::EndOfEarlyData,
            _ => return Err(WireError::Type),
        };
        let len = u32::from_be_bytes([0, high, middle, low]) as usize;
        kind.check_len(len)?;
        Ok((kind, len))
    }

    fn check_len(self, len: usize) -> Result<(), WireError> {
        let max = match self {
            Self::ClientStart => MAX_CLIENT_START_LEN,
            Self::ServerStart | Self::MlsMessage | Self::EndOfEarlyData => MAX_MLS_MESSAGE_LEN,
        };
        if len > max {
            return Err(WireError::TooLong);
        }
        match self {
            Self::ServerStart if len != 32 => Err(WireError::Invalid),
            Self::EndOfEarlyData if len != 0 => Err(WireError::Invalid),
            Self::ClientStart | Self::ServerStart | Self::MlsMessage | Self::EndOfEarlyData => {
                Ok(())
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Handshake<'a> {
    pub(crate) kind: HandshakeType,
    pub(crate) body: &'a [u8],
}

impl<'a> Handshake<'a> {
    pub(crate) fn read_prefix(input: &'a [u8]) -> Result<(Self, &'a [u8]), WireError> {
        let (kind, len) = HandshakeType::read(input.first_chunk().ok_or(WireError::Truncated)?)?;
        let (body, rest) = input[HEADER_LEN..]
            .split_at_checked(len)
            .ok_or(WireError::Truncated)?;
        Ok((Self { kind, body }, rest))
    }

    pub(crate) fn encode(self, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&self.header()?);
        out.extend_from_slice(self.body);
        Ok(())
    }

    pub(crate) fn for_each_fragment<E: From<WireError>>(
        self,
        limit: usize,
        mut write: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        if !(HEADER_LEN..=MAX_PLAINTEXT).contains(&limit) {
            return Err(WireError::Invalid.into());
        }
        let header = self.header()?;
        let first_len = self.body.len().min(limit - HEADER_LEN);
        let mut first = Zeroizing::new(Vec::with_capacity(HEADER_LEN + first_len));
        first.extend_from_slice(&header);
        first.extend_from_slice(&self.body[..first_len]);
        write(&first)?;
        for fragment in self.body[first_len..].chunks(limit) {
            write(fragment)?;
        }
        Ok(())
    }

    fn header(self) -> Result<[u8; HEADER_LEN], WireError> {
        self.kind.check_len(self.body.len())?;
        let [_, high, middle, low] = (self.body.len() as u32).to_be_bytes();
        Ok([self.kind as u8, high, middle, low])
    }

    fn deliver(
        self,
        record_ends: bool,
        on_message: &mut impl FnMut(Self) -> Result<(), WireError>,
    ) -> Result<(), WireError> {
        let switches = match self.kind {
            HandshakeType::ClientStart
            | HandshakeType::ServerStart
            | HandshakeType::EndOfEarlyData => true,
            HandshakeType::MlsMessage => is_epoch_key_update(self.body),
        };
        if switches && !record_ends {
            return Err(WireError::KeySwitch);
        }
        on_message(self)
    }
}

pub(crate) fn clear_record(input: &[u8]) -> Result<Option<&[u8]>, WireError> {
    if input.len() < RECORD_HEADER_LEN {
        return Ok(None);
    }
    let header = RecordHeader::decode(input, false)?;
    if header.kind != OuterType::Handshake {
        return Err(WireError::Type);
    }
    Ok(input.get(RECORD_HEADER_LEN..RECORD_HEADER_LEN + header.len))
}

pub(crate) fn append_clear_record(fragment: &[u8], out: &mut Vec<u8>) -> Result<(), WireError> {
    validate_content(ContentType::Handshake, fragment)?;
    if fragment.len() > MAX_PLAINTEXT {
        return Err(WireError::TooLong);
    }
    out.extend_from_slice(
        &RecordHeader {
            kind: OuterType::Handshake,
            len: fragment.len(),
        }
        .encode()?,
    );
    out.extend_from_slice(fragment);
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Protection {
    Clear,
    PreHandshake,
    EarlyData,
    Epoch(u64),
}

struct Fragment {
    protection: Protection,
    header: [u8; HEADER_LEN],
    header_len: usize,
    body: Zeroizing<Vec<u8>>,
}

impl Fragment {
    fn new(protection: Protection) -> Self {
        Self {
            protection,
            header: [0; HEADER_LEN],
            header_len: 0,
            body: Zeroizing::new(Vec::new()),
        }
    }

    fn extend_header(&mut self, input: &[u8]) -> usize {
        let count = (HEADER_LEN - self.header_len).min(input.len());
        self.header[self.header_len..self.header_len + count].copy_from_slice(&input[..count]);
        self.header_len += count;
        count
    }
}

#[derive(Default)]
pub(crate) struct Reassembly {
    fragment: Option<Fragment>,
}

impl Reassembly {
    pub(crate) fn push(
        &mut self,
        protection: Protection,
        content: ContentType,
        mut input: &[u8],
        mut on_message: impl FnMut(Handshake<'_>) -> Result<(), WireError>,
    ) -> Result<(), WireError> {
        if let Some(mut fragment) = self.fragment.take() {
            if fragment.protection != protection || content != ContentType::Handshake {
                return Err(WireError::Fragment);
            }
            validate_content(content, input)?;
            input = &input[fragment.extend_header(input)..];
            if fragment.header_len != HEADER_LEN {
                self.fragment = Some(fragment);
                return Ok(());
            }
            let (kind, len) = HandshakeType::read(&fragment.header)?;
            let count = (len - fragment.body.len()).min(input.len());
            fragment.body.extend_from_slice(&input[..count]);
            input = &input[count..];
            if fragment.body.len() != len {
                self.fragment = Some(fragment);
                return Ok(());
            }
            Handshake {
                kind,
                body: &fragment.body,
            }
            .deliver(input.is_empty(), &mut on_message)?;
        } else {
            validate_content(content, input)?;
            if content != ContentType::Handshake {
                return Ok(());
            }
        }

        while !input.is_empty() {
            if let Some(header) = input.first_chunk() {
                let (kind, len) = HandshakeType::read(header)?;
                if let Some((body, rest)) = input[HEADER_LEN..].split_at_checked(len) {
                    Handshake { kind, body }.deliver(rest.is_empty(), &mut on_message)?;
                    input = rest;
                    continue;
                }
            }

            // Allocate only for bytes actually received, after checking the declared length.
            let mut fragment = Fragment::new(protection);
            let header_len = fragment.extend_header(input);
            fragment.body.extend_from_slice(&input[header_len..]);
            self.fragment = Some(fragment);
            break;
        }
        Ok(())
    }
}
