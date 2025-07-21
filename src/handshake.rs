// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use futures::{Sink, Stream};
use rusqlite::Connection;
use tokio_util::bytes::Bytes;

use crate::tls_aead::{codec::TlsPacketIn, SecretUpdate, TrafficSecrets};

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ClientIdentity(pub Vec<u8>);

pub(super) trait Handshake {
    type Error: std::error::Error + Send + Sync + 'static;

    fn initialize_storage(connection: &mut Connection) -> Result<(), Self::Error>;

    /// Perform the handshake with the peer and return the key material.
    async fn client_handshake<
        E: std::error::Error + Send + Sync + 'static,
        S: Sink<Bytes, Error = E> + Unpin,
        R: Stream<Item = Result<TlsPacketIn, E>> + Unpin,
    >(
        &mut self,
        rx: &mut R,
        tx: &mut S,
        server_verifying_key: &[u8],
    ) -> Result<TrafficSecrets, Self::Error>;

    async fn server_handshake<
        E: std::error::Error + Send + Sync + 'static,
        S: Sink<Bytes, Error = E> + Unpin,
        R: Stream<Item = Result<TlsPacketIn, E>> + Unpin,
    >(
        &mut self,
        rx: &mut R,
        tx: &mut S,
    ) -> Result<(TrafficSecrets, ClientIdentity), Self::Error>;
}

pub(super) trait CompletedHandshake {
    type Error;

    fn epoch(&self) -> u64;

    async fn update_handshake(&mut self) -> Result<(Option<SecretUpdate>, Vec<u8>), Self::Error>;

    async fn process_signaling_message(
        &mut self,
        message_bytes: &[u8],
    ) -> Result<(Option<SecretUpdate>, Option<Vec<u8>>), Self::Error>;

    async fn delete(&mut self) -> Result<(), Self::Error>;
}
