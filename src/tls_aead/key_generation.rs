// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helper functions to generate keys from a shared secret
use openmls::prelude::SecretVLBytes;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{
        AeadType,
        CryptoError::{self, InvalidLength},
        HashType,
    },
};
use std::sync::Arc;

use super::{ClientSecret, ServerSecret, TrafficSecrets};

pub(crate) const TLS13_IV_SIZE: usize = 12;

/// Helper function to expand a label using HKDF
pub fn hdkf_expand_label(
    crypto: Arc<dyn OpenMlsCrypto>,
    hash: HashType,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Result<SecretVLBytes, CryptoError> {
    const TLS13_PREFIX: &[u8] = b"tls13 ";

    let output_len = match length {
        0..=0xFFFF => u16::to_be_bytes(length as u16),
        _ => return Err(InvalidLength),
    };

    let label_len = match TLS13_PREFIX.len() + label.len() {
        0..=0xFF => u8::to_be_bytes((TLS13_PREFIX.len() + label.len()) as u8),
        _ => return Err(InvalidLength),
    };

    let context_len = match context.len() {
        0..=0xFF => u8::to_be_bytes(context.len() as u8),
        _ => return Err(InvalidLength),
    };

    let info = &[
        &output_len[..],
        &label_len[..],
        TLS13_PREFIX,
        label,
        &context_len[..],
        context,
    ];

    crypto.hkdf_expand(hash, secret, info.concat().as_slice(), length)
}

/// Helper struct to store generated keys
pub(crate) struct GeneratedKeys {
    pub(crate) server_key: SecretVLBytes,
    pub(crate) server_iv: SecretVLBytes,
    pub(crate) client_key: SecretVLBytes,
    pub(crate) client_iv: SecretVLBytes,
}

pub(crate) fn expand_client_secret(
    crypto: Arc<dyn OpenMlsCrypto>,
    hash: HashType,
    client_secret: ClientSecret,
    handshake_hash: &[u8],
    cipher: AeadType,
) -> Result<(SecretVLBytes, SecretVLBytes), CryptoError> {
    let client_secret = hdkf_expand_label(
        crypto.clone(),
        hash,
        client_secret.0.as_slice(),
        b"c ap traffic",
        handshake_hash,
        hash.size(),
    )?;
    let client_key = hdkf_expand_label(
        crypto.clone(),
        hash,
        client_secret.as_slice(),
        b"key",
        &[],
        cipher.key_size(),
    )?;
    let client_iv = hdkf_expand_label(
        crypto.clone(),
        hash,
        client_secret.as_slice(),
        b"iv",
        &[],
        TLS13_IV_SIZE,
    )?;
    Ok((client_key, client_iv))
}

pub(crate) fn expand_server_secret(
    crypto: Arc<dyn OpenMlsCrypto>,
    hash: HashType,
    server_secret: ServerSecret,
    handshake_hash: &[u8],
    cipher: AeadType,
) -> Result<(SecretVLBytes, SecretVLBytes), CryptoError> {
    let server_secret = hdkf_expand_label(
        crypto.clone(),
        hash,
        server_secret.0.as_slice(),
        b"s ap traffic",
        handshake_hash,
        hash.size(),
    )?;
    let server_key = hdkf_expand_label(
        crypto.clone(),
        hash,
        server_secret.as_slice(),
        b"key",
        &[],
        cipher.key_size(),
    )?;
    let server_iv = hdkf_expand_label(
        crypto.clone(),
        hash,
        server_secret.as_slice(),
        b"iv",
        &[],
        TLS13_IV_SIZE,
    )?;
    Ok((server_key, server_iv))
}

/// Helper function to generate keys from a shared secret
pub(crate) fn generate_keys(
    crypto: Arc<dyn OpenMlsCrypto>,
    hash: HashType,
    traffic_secrets: TrafficSecrets,
    handshake_hash: &[u8],
    cipher: AeadType,
) -> Result<GeneratedKeys, CryptoError> {
    let (client_key, client_iv) = expand_client_secret(
        crypto.clone(),
        hash,
        traffic_secrets.client_secret,
        handshake_hash,
        cipher,
    )?;
    let (server_key, server_iv) = expand_server_secret(
        crypto.clone(),
        hash,
        traffic_secrets.server_secret,
        handshake_hash,
        cipher,
    )?;

    Ok(GeneratedKeys {
        server_key,
        server_iv,
        client_key,
        client_iv,
    })
}
