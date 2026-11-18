// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{put_length, Reader, WireError};

pub(crate) const MLS_TLS_VERSION: u16 = 1;

pub(crate) struct LeafInfo<'a> {
    versions: &'a [u8],
    application_protocols: &'a [u8],
}

impl<'a> LeafInfo<'a> {
    pub(crate) fn decode(input: &'a [u8]) -> Result<Self, WireError> {
        let mut reader = Reader::new(input);
        let versions = reader.vector()?;
        let application_protocols = reader.vector()?;
        reader.finish()?;
        if versions.is_empty() || versions.len() % 2 != 0 || application_protocols.is_empty() {
            return Err(WireError::Invalid);
        }
        let mut reader = Reader::new(application_protocols);
        while !reader.remaining().is_empty() {
            read_protocol(&mut reader)?;
        }
        Ok(Self {
            versions,
            application_protocols,
        })
    }

    pub(crate) fn versions(&self) -> impl Iterator<Item = u16> + '_ {
        self.versions
            .as_chunks::<2>()
            .0
            .iter()
            .copied()
            .map(u16::from_be_bytes)
    }

    pub(crate) fn application_protocols(&self) -> impl Iterator<Item = &'a [u8]> {
        let mut reader = Reader::new(self.application_protocols);
        std::iter::from_fn(move || read_protocol(&mut reader).ok())
    }

    pub(crate) fn encode(
        versions: &[u16],
        protocols: &[&[u8]],
        out: &mut Vec<u8>,
    ) -> Result<(), WireError> {
        if versions.is_empty() || protocols.is_empty() {
            return Err(WireError::Invalid);
        }
        let protocol_len = protocols.iter().try_fold(0usize, |total, &protocol| {
            let len = usize::from(protocol_len(protocol)?);
            total.checked_add(1 + len).ok_or(WireError::TooLong)
        })?;
        let version_len = versions.len().checked_mul(2).ok_or(WireError::TooLong)?;
        put_length(version_len, out)?;
        for version in versions {
            out.extend_from_slice(&version.to_be_bytes());
        }
        put_length(protocol_len, out)?;
        for &protocol in protocols {
            write_protocol(protocol, out)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GroupInfo<'a> {
    pub(crate) version: u16,
    pub(crate) application_protocol: &'a [u8],
}

impl<'a> GroupInfo<'a> {
    pub(crate) fn decode(input: &'a [u8]) -> Result<Self, WireError> {
        let mut reader = Reader::new(input);
        let version = reader.u16()?;
        let application_protocol = read_protocol(&mut reader)?;
        reader.finish()?;
        Ok(Self {
            version,
            application_protocol,
        })
    }

    pub(crate) fn encode(self, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&self.version.to_be_bytes());
        write_protocol(self.application_protocol, out)
    }
}

fn read_protocol<'a>(reader: &mut Reader<'a>) -> Result<&'a [u8], WireError> {
    let len = usize::from(reader.byte()?);
    if len == 0 {
        return Err(WireError::Invalid);
    }
    reader.take(len)
}

fn protocol_len(protocol: &[u8]) -> Result<u8, WireError> {
    if protocol.is_empty() {
        return Err(WireError::Invalid);
    }
    u8::try_from(protocol.len()).map_err(|_| WireError::TooLong)
}

fn write_protocol(protocol: &[u8], out: &mut Vec<u8>) -> Result<(), WireError> {
    out.push(protocol_len(protocol)?);
    out.extend_from_slice(protocol);
    Ok(())
}
