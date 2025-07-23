// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, SeedableRng as _};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey};

use super::PreHandshake;

const X25519_PUBLIC_KEY_LENGTH: usize = 32;

#[derive(Debug, Error)]
pub enum X25519Error {
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error("Random number generation error.")]
    RandomError(#[from] rand_core::Error),
}

#[derive(Debug, Clone)]
pub struct X25519Handshake;

impl PreHandshake for X25519Handshake {
    type Error = X25519Error;

    fn initialize_storage(_connection: &mut rusqlite::Connection) -> Result<(), Self::Error> {
        // The handshake is ephemeral, so there's no need to store anything.
        Ok(())
    }

    async fn client_handshake<W: AsyncWrite + Send + Unpin, R: AsyncRead + Send + Unpin>(
        &mut self,
        rx: &mut R,
        tx: &mut W,
    ) -> Result<(Vec<u8>, Uuid), Self::Error> {
        let mut rng = ChaCha20Rng::from_rng(OsRng)?;
        let private_key = EphemeralSecret::random_from_rng(&mut rng);

        let public_key = PublicKey::from(&private_key);

        tx.write_all(public_key.as_bytes()).await?;

        let mut server_pk_bytes = [0u8; X25519_PUBLIC_KEY_LENGTH];
        rx.read_exact(&mut server_pk_bytes).await?;

        let server_pk = server_pk_bytes.into();
        let shared_secret = private_key.diffie_hellman(&server_pk);

        Ok((shared_secret.to_bytes().to_vec(), Uuid::nil()))
    }

    async fn server_handshake<W: AsyncWrite + Unpin, R: AsyncRead + Unpin>(
        &mut self,
        rx: &mut R,
        tx: &mut W,
    ) -> Result<(Vec<u8>, Uuid), Self::Error> {
        let mut client_pk_bytes = [0u8; X25519_PUBLIC_KEY_LENGTH];
        rx.read_exact(&mut client_pk_bytes).await?;
        let client_pk = client_pk_bytes.into();

        let mut rng = ChaCha20Rng::from_rng(OsRng)?;
        let private_key = EphemeralSecret::random_from_rng(&mut rng);

        let public_key = PublicKey::from(&private_key);
        tx.write_all(public_key.as_bytes()).await?;

        let shared_secret = private_key.diffie_hellman(&client_pk);

        Ok((shared_secret.to_bytes().to_vec(), Uuid::nil()))
    }
}
