// SPDX-FileCopyrightText: 2026 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::prelude::{
    tls_codec::Deserialize as _, ContentType, MlsMessageBodyIn, MlsMessageIn, Sender,
};

use super::{put_optional, put_vector, Reader, WireError, MLS_VERSION, TWO_PARTY_WIRE_FORMAT};

pub(crate) const MAX_MLS_MESSAGE_LEN: usize = 1 << 18;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReconnectContent<'a> {
    pub(crate) number: u64,
    pub(crate) nonce: &'a [u8; 32],
    pub(crate) early_data: bool,
    pub(crate) current: &'a [u8],
    pub(crate) pending: Option<&'a [u8]>,
}

impl<'a> ReconnectContent<'a> {
    fn read(reader: &mut Reader<'a>) -> Result<Self, WireError> {
        let number = reader.u64()?;
        let nonce = reader.array()?;
        let early_data = reader.byte()?;
        let connection_id = reader.vector()?;
        if number == 0 || early_data > 1 || !connection_id.is_empty() {
            return Err(WireError::Invalid);
        }
        Ok(Self {
            number,
            nonce,
            early_data: early_data == 1,
            current: reader.vector()?,
            pending: reader.optional_vector()?,
        })
    }

    pub(crate) fn encode(self, out: &mut Vec<u8>) -> Result<(), WireError> {
        if self.number == 0 {
            return Err(WireError::Invalid);
        }
        out.extend_from_slice(&self.number.to_be_bytes());
        out.extend_from_slice(self.nonce);
        // The ordered binding carries an empty connection_id.
        out.extend_from_slice(&[u8::from(self.early_data), 0]);
        put_vector(self.current, out)?;
        put_optional(self.pending, out)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Reconnect<'a> {
    pub(crate) content: ReconnectContent<'a>,
    pub(crate) current_binder: &'a [u8],
    pub(crate) pending_binder: Option<&'a [u8]>,
}

impl<'a> Reconnect<'a> {
    fn read(reader: &mut Reader<'a>) -> Result<Self, WireError> {
        let content = ReconnectContent::read(reader)?;
        let current_binder = reader.vector()?;
        let pending_binder = reader.optional_vector()?;
        if content.pending.is_some() != pending_binder.is_some() {
            return Err(WireError::Invalid);
        }
        Ok(Self {
            content,
            current_binder,
            pending_binder,
        })
    }

    pub(crate) fn encode(self, out: &mut Vec<u8>) -> Result<(), WireError> {
        if self.content.pending.is_some() != self.pending_binder.is_some() {
            return Err(WireError::Invalid);
        }
        self.content.encode(out)?;
        put_vector(self.current_binder, out)?;
        put_optional(self.pending_binder, out)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ChallengeContent<'a> {
    pub(crate) epoch: u8,
    pub(crate) challenge: &'a [u8; 32],
    pub(crate) early_data: u8,
}

impl<'a> ChallengeContent<'a> {
    fn read(reader: &mut Reader<'a>) -> Result<Self, WireError> {
        let value = Self {
            epoch: reader.byte()?,
            challenge: reader.array()?,
            early_data: reader.byte()?,
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn encode(self, out: &mut Vec<u8>) -> Result<(), WireError> {
        self.validate()?;
        out.push(self.epoch);
        out.extend_from_slice(self.challenge);
        out.push(self.early_data);
        Ok(())
    }

    fn validate(self) -> Result<(), WireError> {
        if self.epoch > 2 || self.early_data > 2 {
            return Err(WireError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TwoPartyMessage<'a> {
    EpochKeyUpdate {
        epoch: u64,
        confirmation: &'a [u8],
    },
    Reconnect(Reconnect<'a>),
    Challenge {
        content: ChallengeContent<'a>,
        proof: &'a [u8],
    },
    ChallengeResponse {
        epoch: u8,
        response: &'a [u8],
    },
    Adopted(&'a [u8]),
    Reset(&'a [u8]),
}

impl<'a> TwoPartyMessage<'a> {
    fn read(reader: &mut Reader<'a>) -> Result<Self, WireError> {
        Ok(match reader.byte()? {
            1 => Self::EpochKeyUpdate {
                epoch: reader.u64()?,
                confirmation: reader.vector()?,
            },
            2 => Self::Reconnect(Reconnect::read(reader)?),
            3 => Self::Challenge {
                content: ChallengeContent::read(reader)?,
                proof: reader.vector()?,
            },
            4 => {
                let epoch = reader.byte()?;
                if epoch > 1 {
                    return Err(WireError::Invalid);
                }
                Self::ChallengeResponse {
                    epoch,
                    response: reader.vector()?,
                }
            }
            5 => Self::Adopted(reader.vector()?),
            6 => Self::Reset(reader.vector()?),
            _ => return Err(WireError::Type),
        })
    }

    pub(crate) fn write_mls(self, out: &mut Vec<u8>) -> Result<(), WireError> {
        let start = out.len();
        let result = self.write(out).and_then(|()| {
            if out.len() - start <= MAX_MLS_MESSAGE_LEN {
                Ok(())
            } else {
                Err(WireError::TooLong)
            }
        });
        if result.is_err() {
            out.truncate(start);
        }
        result
    }

    fn write(self, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.extend_from_slice(&MLS_VERSION.to_be_bytes());
        out.extend_from_slice(&TWO_PARTY_WIRE_FORMAT.to_be_bytes());
        match self {
            Self::EpochKeyUpdate {
                epoch,
                confirmation,
            } => {
                out.push(1);
                out.extend_from_slice(&epoch.to_be_bytes());
                put_vector(confirmation, out)
            }
            Self::Reconnect(reconnect) => {
                out.push(2);
                reconnect.encode(out)
            }
            Self::Challenge { content, proof } => {
                out.push(3);
                content.encode(out)?;
                put_vector(proof, out)
            }
            Self::ChallengeResponse { epoch, response } => {
                if epoch > 1 {
                    return Err(WireError::Invalid);
                }
                out.extend_from_slice(&[4, epoch]);
                put_vector(response, out)
            }
            Self::Adopted(proof) => {
                out.push(5);
                put_vector(proof, out)
            }
            Self::Reset(token) => {
                out.push(6);
                put_vector(token, out)
            }
        }
    }
}

pub(crate) enum MlsMessage<'a> {
    Standard(Box<MlsMessageBodyIn>),
    TwoParty(TwoPartyMessage<'a>),
}

impl<'a> MlsMessage<'a> {
    pub(crate) fn decode(input: &'a [u8]) -> Result<Self, WireError> {
        if input.len() > MAX_MLS_MESSAGE_LEN {
            return Err(WireError::TooLong);
        }
        let mut reader = Reader::new(input);
        if reader.u16()? != MLS_VERSION {
            return Err(WireError::Version);
        }
        match reader.u16()? {
            TWO_PARTY_WIRE_FORMAT => {
                let message = TwoPartyMessage::read(&mut reader)?;
                reader.finish()?;
                Ok(Self::TwoParty(message))
            }
            // PublicMessage (Commit), Welcome (ServerHello), KeyPackage (ClientHello).
            1 | 3 | 5 => {
                let message = MlsMessageIn::tls_deserialize_exact(input)
                    .map_err(|_| WireError::Invalid)?
                    .extract();
                if let MlsMessageBodyIn::PublicMessage(commit) = &message {
                    let Sender::Member(_) = commit.sender() else {
                        return Err(WireError::Type);
                    };
                    if commit.content_type() != ContentType::Commit {
                        return Err(WireError::Type);
                    }
                }
                Ok(Self::Standard(Box::new(message)))
            }
            _ => Err(WireError::Type),
        }
    }
}

pub(crate) fn is_epoch_key_update(input: &[u8]) -> bool {
    let [major, minor, high, low, 1, ..] = input else {
        return false;
    };
    if u16::from_be_bytes([*major, *minor]) != MLS_VERSION
        || u16::from_be_bytes([*high, *low]) != TWO_PARTY_WIRE_FORMAT
    {
        return false;
    }
    matches!(
        MlsMessage::decode(input),
        Ok(MlsMessage::TwoParty(TwoPartyMessage::EpochKeyUpdate {
            epoch: _,
            confirmation: _
        }))
    )
}
