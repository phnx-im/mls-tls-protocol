// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use hpqmls::messages::{HpqMlsMessageIn, HpqMlsMessageOut};
use openmls::prelude::{MlsMessageIn, MlsMessageOut, TlsDeserialize, TlsSerialize, TlsSize};
use serde::{Deserialize, Serialize};

#[repr(u16)]
#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize, PartialEq)]
pub(super) enum ProtocolVersion {
    /// Version 0.1
    V01,
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self::V01
    }
}

#[derive(Debug, TlsDeserialize, TlsSize)]
pub(super) struct MlsTlsHandshakeIn {
    pub(super) version: ProtocolVersion,
    pub(super) payload: HandshakePayloadIn,
}

#[derive(Debug, TlsSerialize, TlsSize)]
pub(super) struct MlsTlsHandshakeOut {
    pub(super) version: ProtocolVersion,
    pub(super) payload: HandshakePayloadOut,
}

#[repr(u16)]
#[derive(Debug, TlsDeserialize, TlsSize)]
pub(super) enum HandshakePayloadIn {
    ClientHello(Box<ClientHelloIn>),
    Resumption(ResumptionIn),
}

#[repr(u16)]
#[derive(Debug, TlsSerialize, TlsSize)]
pub(super) enum HandshakePayloadOut {
    ClientHello(Box<ClientHelloOut>),
    #[allow(dead_code)]
    Resumption(ResumptionOut),
}

#[derive(Debug, TlsDeserialize, TlsSize)]
pub(super) struct ClientHelloIn {
    pub(super) key_package: HpqMlsMessageIn,
}

#[derive(Debug, TlsSerialize, TlsSize)]
pub(super) struct ClientHelloOut {
    pub(super) key_package: HpqMlsMessageOut,
}

#[derive(Debug, TlsDeserialize, TlsSize)]
pub(super) struct ServerHelloIn {
    pub(super) welcome: HpqMlsMessageIn,
}

#[derive(Debug, TlsSerialize, TlsSize)]
pub(super) struct ServerHelloOut {
    pub(super) welcome: HpqMlsMessageOut,
}

#[derive(Debug, TlsDeserialize, TlsSize)]
pub(super) struct ResumptionIn {
    pub(super) commit: HandshakeMessageIn,
}

#[derive(Debug, TlsSerialize, TlsSize)]
pub(super) struct ResumptionOut {
    pub(super) commit: HandshakeMessageOut,
}

// === In-band data & signaling ===

#[repr(u16)]
#[derive(Debug, TlsDeserialize, TlsSize)]
#[allow(clippy::large_enum_variant)]
pub(super) enum SignalingMessageIn {
    ConnectionUpdate(ConnectionUpdateIn),
    ConnectionConfirmation(EpochKeyUpdate),
    EpochKeyUpdate(EpochKeyUpdate),
    KeyUpdate(KeyUpdate),
}

impl SignalingMessageIn {
    pub(super) fn message_type(&self) -> &'static str {
        match self {
            SignalingMessageIn::ConnectionUpdate(_) => "ConnectionUpdate",
            SignalingMessageIn::ConnectionConfirmation(_) => "ConnectionConfirmation",
            SignalingMessageIn::EpochKeyUpdate(_) => "EpochKeyUpdate",
            SignalingMessageIn::KeyUpdate(_) => "KeyUpdate",
        }
    }
}

#[repr(u16)]
#[derive(Debug, TlsSerialize, TlsSize)]
#[allow(clippy::large_enum_variant)]
pub(super) enum SignalingMessageOut {
    ConnectionUpdate(ConnectionUpdateOut),
    ConnectionConfirmation(EpochKeyUpdate),
    EpochKeyUpdate(EpochKeyUpdate),
    #[allow(dead_code)]
    KeyUpdate(KeyUpdate),
}

#[derive(Debug, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub(super) enum HandshakeMessageIn {
    HpqMls(Box<HpqMlsMessageIn>),
    Mls(Box<MlsMessageIn>),
}

impl From<HpqMlsMessageIn> for HandshakeMessageIn {
    fn from(msg: HpqMlsMessageIn) -> Self {
        HandshakeMessageIn::HpqMls(Box::new(msg))
    }
}

impl From<MlsMessageIn> for HandshakeMessageIn {
    fn from(msg: MlsMessageIn) -> Self {
        HandshakeMessageIn::Mls(Box::new(msg))
    }
}

#[derive(Debug, Clone, TlsSerialize, TlsSize, Serialize, Deserialize)]
#[repr(u8)]
pub(super) enum HandshakeMessageOut {
    HpqMls(Box<HpqMlsMessageOut>),
    Mls(Box<MlsMessageOut>),
}

impl From<HpqMlsMessageOut> for HandshakeMessageOut {
    fn from(msg: HpqMlsMessageOut) -> Self {
        HandshakeMessageOut::HpqMls(Box::new(msg))
    }
}

impl From<MlsMessageOut> for HandshakeMessageOut {
    fn from(msg: MlsMessageOut) -> Self {
        HandshakeMessageOut::Mls(Box::new(msg))
    }
}

#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub(super) struct EpochKeyUpdate {
    pub(super) epoch: u64,
}

#[derive(Debug, TlsDeserialize, TlsSize)]
pub(super) struct ConnectionUpdateIn {
    pub(super) update_requested: Boolean,
    pub(super) mls_commit: HandshakeMessageIn,
}

#[derive(Debug, TlsSerialize, TlsSize)]
pub(super) struct ConnectionUpdateOut {
    pub(super) update_requested: Boolean,
    pub(super) mls_commit: HandshakeMessageOut,
}

#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub(super) struct KeyUpdate {
    update_requested: Boolean,
}

#[repr(u8)]
#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub(super) enum Boolean {
    True,
    False,
}

impl From<Boolean> for bool {
    fn from(b: Boolean) -> Self {
        match b {
            Boolean::True => true,
            Boolean::False => false,
        }
    }
}

impl From<bool> for Boolean {
    fn from(b: bool) -> Self {
        if b {
            Boolean::True
        } else {
            Boolean::False
        }
    }
}

// === Alerts ===

#[repr(u8)]
#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub(super) enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}

#[repr(u8)]
#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub(super) enum AlertDescription {
    UnexpectedMessage = 10,
    HandshakeFailure = 40,
    DecodeError = 50,
    DecryptError = 51,
    ProtocolVersion = 70,
}

#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub(super) struct Alert {
    pub(super) level: AlertLevel,
    pub(super) description: AlertDescription,
}
