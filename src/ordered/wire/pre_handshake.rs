// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::handshake::{Handshake, HandshakeType, MAX_CLIENT_START_LEN};
use super::{put_length, put_optional, put_vector, Reader, WireError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CipherSuite {
    pub(crate) kdf: u16,
    pub(crate) aead: u16,
}

impl CipherSuite {
    fn read(reader: &mut Reader<'_>) -> Result<Self, WireError> {
        let suite = Self {
            kdf: reader.u16()?,
            aead: reader.u16()?,
        };
        if suite.aead == 0xffff {
            return Err(WireError::Invalid);
        }
        Ok(suite)
    }

    fn write(self, out: &mut Vec<u8>) -> Result<(), WireError> {
        if self.aead == 0xffff {
            return Err(WireError::Invalid);
        }
        out.extend_from_slice(&self.kdf.to_be_bytes());
        out.extend_from_slice(&self.aead.to_be_bytes());
        Ok(())
    }
}

pub(crate) enum Config<'a> {
    Hpke {
        id: u8,
        kem: u16,
        public_key: &'a [u8],
        cipher_suites: Vec<CipherSuite>,
    },
    Psk {
        id: u8,
        cipher_suite: CipherSuite,
    },
}

impl<'a> Config<'a> {
    pub(crate) fn decode(input: &'a [u8]) -> Result<Self, WireError> {
        let mut reader = Reader::new(input);
        let id = reader.byte()?;
        let config = match reader.byte()? {
            1 => {
                let kem = reader.u16()?;
                let public_key = reader.vector()?;
                let mut ciphers = Reader::new(reader.vector()?);
                let mut cipher_suites = Vec::new();
                while !ciphers.remaining().is_empty() {
                    cipher_suites.push(CipherSuite::read(&mut ciphers)?);
                }
                Self::Hpke {
                    id,
                    kem,
                    public_key,
                    cipher_suites,
                }
            }
            2 => Self::Psk {
                id,
                cipher_suite: CipherSuite::read(&mut reader)?,
            },
            _ => return Err(WireError::Type),
        };
        reader.finish()?;
        Ok(config)
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        match self {
            Self::Hpke {
                id,
                kem,
                public_key,
                cipher_suites,
            } => {
                out.extend_from_slice(&[*id, 1]);
                out.extend_from_slice(&kem.to_be_bytes());
                put_vector(public_key, out)?;
                let len = cipher_suites
                    .len()
                    .checked_mul(4)
                    .ok_or(WireError::TooLong)?;
                put_length(len, out)?;
                for suite in cipher_suites {
                    suite.write(out)?;
                }
                Ok(())
            }
            Self::Psk { id, cipher_suite } => {
                out.extend_from_slice(&[*id, 2]);
                cipher_suite.write(out)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SessionReferences<'a> {
    pub(crate) client_random: &'a [u8; 32],
    pub(crate) current: &'a [u8],
    pub(crate) pending: Option<&'a [u8]>,
}

impl<'a> SessionReferences<'a> {
    pub(crate) fn write_prefix(self, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.push(3);
        out.extend_from_slice(self.client_random);
        put_vector(self.current, out)?;
        put_optional(self.pending, out)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClientStartPrefix<'a> {
    Hpke {
        config: u8,
        suite: CipherSuite,
        enc: &'a [u8],
    },
    Psk {
        config: u8,
        client_random: &'a [u8; 32],
    },
    Session {
        references: SessionReferences<'a>,
        current_key: &'a [u8],
        pending_key: Option<&'a [u8]>,
    },
}

impl ClientStartPrefix<'_> {
    pub(crate) fn encode(self, out: &mut Vec<u8>) -> Result<(), WireError> {
        match self {
            Self::Hpke { config, suite, enc } => {
                out.extend_from_slice(&[1, config]);
                suite.write(out)?;
                put_vector(enc, out)
            }
            Self::Psk {
                config,
                client_random,
            } => {
                out.extend_from_slice(&[2, config]);
                out.extend_from_slice(client_random);
                Ok(())
            }
            Self::Session {
                references,
                current_key,
                pending_key,
            } => {
                if references.pending.is_some() != pending_key.is_some() {
                    return Err(WireError::Invalid);
                }
                references.write_prefix(out)?;
                put_vector(current_key, out)?;
                put_optional(pending_key, out)
            }
        }
    }
}

pub(crate) struct ClientStart<'a> {
    pub(crate) prefix: ClientStartPrefix<'a>,
    pub(crate) wrap_aad: Option<&'a [u8]>,
    pub(crate) payload_aad: &'a [u8],
    pub(crate) payload: &'a [u8],
}

impl<'a> ClientStart<'a> {
    pub(crate) fn decode(input: &'a [u8]) -> Result<Self, WireError> {
        if input.len() > MAX_CLIENT_START_LEN {
            return Err(WireError::TooLong);
        }
        let mut reader = Reader::new(input);
        let mut wrap_aad = None;
        let prefix = match reader.byte()? {
            1 => ClientStartPrefix::Hpke {
                config: reader.byte()?,
                suite: CipherSuite::read(&mut reader)?,
                enc: reader.vector()?,
            },
            2 => ClientStartPrefix::Psk {
                config: reader.byte()?,
                client_random: reader.array()?,
            },
            3 => {
                let references = SessionReferences {
                    client_random: reader.array()?,
                    current: reader.vector()?,
                    pending: reader.optional_vector()?,
                };
                wrap_aad = Some(&input[..input.len() - reader.remaining().len()]);
                let current_key = reader.vector()?;
                let pending_key = reader.optional_vector()?;
                if references.pending.is_some() != pending_key.is_some() {
                    return Err(WireError::Invalid);
                }
                ClientStartPrefix::Session {
                    references,
                    current_key,
                    pending_key,
                }
            }
            _ => return Err(WireError::Type),
        };
        let payload_aad = &input[..input.len() - reader.remaining().len()];
        let payload = reader.vector()?;
        reader.finish()?;
        Ok(Self {
            prefix,
            wrap_aad,
            payload_aad,
            payload,
        })
    }
}

pub(crate) fn server_start(input: &[u8]) -> Result<&[u8; 32], WireError> {
    let mut reader = Reader::new(input);
    let random = reader.array()?;
    reader.finish()?;
    Ok(random)
}

pub(crate) fn open_payload(input: &[u8]) -> Result<&[u8], WireError> {
    let (handshake, padding) = Handshake::read_prefix(input)?;
    if handshake.kind != HandshakeType::MlsMessage {
        return Err(WireError::Type);
    }
    if padding.iter().any(|&byte| byte != 0) {
        return Err(WireError::Invalid);
    }
    Ok(handshake.body)
}
