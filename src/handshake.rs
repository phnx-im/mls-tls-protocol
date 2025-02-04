// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use rusqlite::Connection;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::tls_aead::{SecretUpdate, TrafficSecrets};

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ClientIdentity(pub Vec<u8>);
pub(super) trait Handshake<T: AsyncWrite + AsyncWriteExt, R: AsyncRead + AsyncReadExt> {
    type Error;
    type Reader;
    type Writer;

    fn initialize_storage(connection: &mut Connection) -> Result<(), Self::Error>;

    /// Perform the handshake with the peer and return the key material.
    async fn client_handshake(
        &mut self,
        rx: &mut Self::Reader,
        tx: &mut Self::Writer,
    ) -> Result<TrafficSecrets, Self::Error>;

    async fn server_handshake(
        &mut self,
        rx: &mut Self::Reader,
        tx: &mut Self::Writer,
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
