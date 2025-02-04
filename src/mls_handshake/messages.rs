// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::prelude::{
    tls_codec, MlsMessageIn, MlsMessageOut, TlsDeserialize, TlsSerialize, TlsSize,
};

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

#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
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
#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub(super) enum HandshakePayloadIn {
    ClientHello(ClientHelloIn),
    Resumption(ResumptionIn),
}

#[repr(u16)]
#[derive(Debug, TlsSerialize, TlsSize)]
pub(super) enum HandshakePayloadOut {
    ClientHello(ClientHelloOut),
    #[allow(dead_code)]
    Resumption(ResumptionOut),
}

#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub(super) struct ClientHelloIn {
    pub(super) key_package: MlsMessageIn,
}

#[derive(Debug, TlsSerialize, TlsSize)]
pub(super) struct ClientHelloOut {
    pub(super) key_package: MlsMessageOut,
}

#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub(super) struct ServerHelloIn {
    pub(super) welcome: MlsMessageIn,
}

#[derive(Debug, TlsSerialize, TlsSize)]
pub(super) struct ServerHelloOut {
    pub(super) welcome: MlsMessageOut,
}

#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub(super) struct ResumptionIn {
    pub(super) commit: MlsMessageIn,
}

#[derive(Debug, TlsSerialize, TlsSize)]
pub(super) struct ResumptionOut {
    pub(super) commit: MlsMessageOut,
}

// === In-band data & signaling ===

#[repr(u16)]
#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
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

#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub(super) struct EpochKeyUpdate {
    pub(super) epoch: u64,
}

#[derive(Debug, TlsDeserialize, TlsSerialize, TlsSize)]
pub(super) struct ConnectionUpdateIn {
    pub(super) update_requested: Boolean,
    pub(super) mls_commit: MlsMessageIn,
}

#[derive(Debug, TlsSerialize, TlsSize)]
pub(super) struct ConnectionUpdateOut {
    pub(super) update_requested: Boolean,
    pub(super) mls_commit: MlsMessageOut,
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
