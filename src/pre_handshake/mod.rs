// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, types::CryptoError, OpenMlsProvider};
use rusqlite::Connection;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    encryption_provider::KEY_SCHEDULE_HASH_FUNCTION,
    tls_aead::{ClientSecret, ServerSecret, TrafficSecrets},
};

pub mod psk;
pub mod x25519;

#[trait_variant::make(Send)]
pub trait PreHandshake {
    type Error: std::error::Error + Send + Sync + 'static;

    fn initialize_storage(connection: &mut Connection) -> Result<(), Self::Error>;

    /// Perform the handshake with the peer and return the key material.
    async fn client_handshake<W: AsyncWrite + Send + Unpin, R: AsyncRead + Send + Unpin>(
        &mut self,
        rx: &mut R,
        tx: &mut W,
    ) -> Result<Vec<u8>, Self::Error>;

    async fn server_handshake<W: AsyncWrite + Send + Unpin, R: AsyncRead + Send + Unpin>(
        &mut self,
        rx: &mut R,
        tx: &mut W,
    ) -> Result<Vec<u8>, Self::Error>;
}

pub(crate) fn derive_traffic_secrets(base_secret: &[u8]) -> Result<TrafficSecrets, CryptoError> {
    const SECRET_LEN: usize = KEY_SCHEDULE_HASH_FUNCTION.size();
    let rust_crypto = OpenMlsRustCrypto::default();
    let client_info = b"X25519 MLS-TLS Pre-Handshake Client Secret";
    let server_info = b"X25519 MLS-TLS Pre-Handshake Server Secret";
    let crypto_provider = rust_crypto.crypto();
    let intermediate_secret =
        crypto_provider.hkdf_extract(KEY_SCHEDULE_HASH_FUNCTION, &[], base_secret)?;
    let client_secret = crypto_provider.hkdf_expand(
        KEY_SCHEDULE_HASH_FUNCTION,
        intermediate_secret.as_slice(),
        client_info,
        SECRET_LEN,
    )?;
    let server_secret = crypto_provider.hkdf_expand(
        KEY_SCHEDULE_HASH_FUNCTION,
        intermediate_secret.as_slice(),
        server_info,
        SECRET_LEN,
    )?;
    Ok(TrafficSecrets {
        client_secret: ClientSecret(client_secret.as_slice().to_vec()),
        server_secret: ServerSecret(server_secret.as_slice().to_vec()),
    })
}
