// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::convert::Infallible;

use super::*;

#[derive(Debug, Clone)]
pub struct Psk {
    key: Vec<u8>,
}

impl Psk {
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }
}

impl PreHandshake for Psk {
    type Error = Infallible;

    fn initialize_storage(_connection: &mut rusqlite::Connection) -> Result<(), Self::Error> {
        // The handshake is ephemeral, so there's no need to store anything.
        Ok(())
    }

    async fn client_handshake<W: AsyncWrite + Send + Unpin, R: AsyncRead + Send + Unpin>(
        &mut self,
        _rx: &mut R,
        _tx: &mut W,
    ) -> Result<(Vec<u8>, Uuid), Self::Error> {
        Ok((self.key.clone(), Uuid::nil()))
    }

    async fn server_handshake<W: AsyncWrite + Unpin, R: AsyncRead + Unpin>(
        &mut self,
        _rx: &mut R,
        _tx: &mut W,
    ) -> Result<(Vec<u8>, Uuid), Self::Error> {
        Ok((self.key.clone(), Uuid::nil()))
    }
}
