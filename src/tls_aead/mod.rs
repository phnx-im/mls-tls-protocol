// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # TLS AEAD Codec
//!
//! This module provides a codec for encrypting and decrypting data using the
//! TLS AEAD scheme according to RFC 8446.

use key_generation::{expand_client_secret, expand_server_secret, generate_keys, TLS13_IV_SIZE};
use openmls::prelude::SecretVLBytes;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{AeadType, CryptoError, HashType},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

pub mod codec;
mod key_generation;

pub(crate) const TLS_APP_DATA: u8 = 0x17;
const TLS_VERSION: u16 = 0x0303;
const TLS_MAX_RECORD_SIZE: u16 = 2 << 14;
const TLS_HDR_SIZE: usize = 5;
const TLS_AEAD_TAG_SIZE: usize = 16;
const MIN_RECORD_SIZE: usize = TLS_HDR_SIZE + TLS_AEAD_TAG_SIZE + 1;

#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize)]
pub(crate) struct ServerSecret(pub(crate) Vec<u8>);
#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize)]
pub(crate) struct ClientSecret(pub(crate) Vec<u8>);

#[derive(Debug, Default, PartialEq, Clone, Serialize, Deserialize)]
pub(crate) struct TrafficSecrets {
    pub(crate) client_secret: ClientSecret,
    pub(crate) server_secret: ServerSecret,
}

#[derive(Debug)]
pub(super) enum SecretUpdate {
    ClientSecret(ClientSecret),
    ServerSecret(ServerSecret),
    Both(TrafficSecrets),
}

#[cfg(test)]
impl TrafficSecrets {
    pub(crate) fn update(&mut self, update: SecretUpdate) {
        match update {
            SecretUpdate::ClientSecret(secret) => self.client_secret = secret,
            SecretUpdate::ServerSecret(secret) => self.server_secret = secret,
            SecretUpdate::Both(secrets) => {
                self.client_secret = secrets.client_secret;
                self.server_secret = secrets.server_secret;
            }
        }
    }
}

/// # TLS AEAD codec error
#[derive(Debug, Error)]
pub enum TlsAeadCodecError {
    #[error("Invalid data")]
    InvalidData,
    #[error("Invalid MAC")]
    InvalidMac,
    #[error("Crypto error")]
    CryptoError(CryptoError),
    #[error("Invalid length")]
    InvalidLength,
}

impl From<CryptoError> for TlsAeadCodecError {
    fn from(e: CryptoError) -> Self {
        TlsAeadCodecError::CryptoError(e)
    }
}

/// # TLS AEAD codec
/// This struct provides the functionality to encrypt and decrypt data using the
/// TLS AEAD scheme according to RFC 8446.
pub struct TlsAeadCodec {
    /// Send key
    send_key: SecretVLBytes,
    /// Send IV
    send_iv: SecretVLBytes,
    /// Receive key
    recv_key: SecretVLBytes,
    /// Receive IV
    recv_iv: SecretVLBytes,
    /// Send sequence number
    send_seq: u64,
    /// Receive sequence number
    recv_seq: u64,
    /// AEAD cipher
    cipher: AeadType,
    /// Hash algorithm
    hash: HashType,
    /// Maximum frame size
    max_frame_size: u16,
    /// Crypto provider
    crypto: Arc<dyn OpenMlsCrypto>,
}

/// TLS AEAD encoder/decoder implementation
impl TlsAeadCodec {
    /// Create a new TLS AEAD encoder/decoder for client/server
    /// # Arguments
    /// * `crypto` - The crypto provider
    /// * `is_server` - Flag indicating if the codec is for the server or the client (true = server, false = client)
    /// * `secret` - The shared secret from the handshake protocol
    /// * `handshake_hash` - The hash of the handshake messages
    /// * `hash` - The hash algorithm
    /// * `cipher` - The AEAD cipher
    pub(crate) fn new(
        crypto: Arc<dyn OpenMlsCrypto>,
        is_server: bool,
        traffic_secrets: TrafficSecrets,
        handshake_hash: &[u8],
        hash: HashType,
        cipher: AeadType,
    ) -> Result<Self, TlsAeadCodecError> {
        let keys = generate_keys(
            crypto.clone(),
            hash,
            traffic_secrets,
            handshake_hash,
            cipher,
        )?;

        let (send_key, send_iv, recv_key, recv_iv) = match is_server {
            true => (
                keys.server_key,
                keys.server_iv,
                keys.client_key,
                keys.client_iv,
            ),
            false => (
                keys.client_key,
                keys.client_iv,
                keys.server_key,
                keys.server_iv,
            ),
        };

        Ok(Self {
            send_key,
            send_iv,
            recv_key,
            recv_iv,
            send_seq: 0,
            recv_seq: 0,
            cipher,
            hash,
            max_frame_size: TLS_MAX_RECORD_SIZE,
            crypto,
        })
    }

    pub(crate) fn update_traffic_secrets(
        &mut self,
        update: SecretUpdate,
        is_server: bool,
    ) -> Result<(), TlsAeadCodecError> {
        match update {
            SecretUpdate::ClientSecret(client_secret) => {
                let (client_key, client_iv) = expand_client_secret(
                    self.crypto.clone(),
                    self.hash,
                    client_secret,
                    &[],
                    self.cipher,
                )?;
                if is_server {
                    self.recv_key = client_key;
                    self.recv_iv = client_iv;
                } else {
                    self.send_key = client_key;
                    self.send_iv = client_iv;
                }
            }
            SecretUpdate::ServerSecret(server_secret) => {
                let (server_key, server_iv) = expand_server_secret(
                    self.crypto.clone(),
                    self.hash,
                    server_secret,
                    &[],
                    self.cipher,
                )?;
                if is_server {
                    self.send_key = server_key;
                    self.send_iv = server_iv;
                } else {
                    self.recv_key = server_key;
                    self.recv_iv = server_iv;
                }
            }
            SecretUpdate::Both(traffic_secrets) => {
                let (client_key, client_iv) = expand_client_secret(
                    self.crypto.clone(),
                    self.hash,
                    traffic_secrets.client_secret,
                    &[],
                    self.cipher,
                )?;
                let (server_key, server_iv) = expand_server_secret(
                    self.crypto.clone(),
                    self.hash,
                    traffic_secrets.server_secret,
                    &[],
                    self.cipher,
                )?;
                if is_server {
                    self.send_key = server_key;
                    self.send_iv = server_iv;
                    self.recv_key = client_key;
                    self.recv_iv = client_iv;
                } else {
                    self.send_key = client_key;
                    self.send_iv = client_iv;
                    self.recv_key = server_key;
                    self.recv_iv = server_iv;
                }
            }
        }
        Ok(())
    }

    /// Create an IV from the IV and sequence number
    fn make_iv(iv: &[u8], seq: u64) -> Result<Vec<u8>, CryptoError> {
        let mut ret = match iv.len() {
            TLS13_IV_SIZE => iv.to_vec(),
            _ => return Err(CryptoError::InvalidLength),
        };
        for (i, byte) in seq.to_le_bytes().iter().enumerate() {
            let idx = iv.len() - 1 - i;
            ret[idx] ^= byte;
        }
        Ok(ret)
    }

    /// Encrypt application data with TLS header
    /// # Arguments
    /// * `data` - The data to encode
    /// # Returns
    /// A vector of TLS encoded application data frames if successful or an error
    pub fn encrypt_with_header(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>, TlsAeadCodecError> {
        let mut frames = Vec::new();
        for chunk in data.chunks(self.max_frame_size as usize) {
            let to_encode = [chunk, &[TLS_APP_DATA]].concat();

            //Associated data is composed of the TLS record
            let associated_data = [
                &[TLS_APP_DATA],
                &TLS_VERSION.to_be_bytes()[..],
                &((chunk.len() + self.cipher.tag_size() + 1) as u16).to_be_bytes(),
            ]
            .concat();

            let encrypted = self.crypto.aead_encrypt(
                self.cipher,
                self.send_key.as_slice(),
                to_encode.as_slice(),
                Self::make_iv(self.send_iv.as_ref(), self.send_seq)?.as_slice(),
                associated_data.as_slice(),
            )?;

            //Compose TLS APP DATA message
            let tls_msg_out = [
                &[TLS_APP_DATA],
                &TLS_VERSION.to_be_bytes()[..],
                &(encrypted.len() as u16).to_be_bytes(),
                &encrypted[..],
            ]
            .concat();

            frames.push(tls_msg_out);
            self.send_seq += 1;
        }
        Ok(frames)
    }

    /// Encrypt application data (without TLS header)
    /// # Arguments
    /// * `data` - The data to encrypt
    /// # Returns
    /// A vector of encrypted application data frames if successful or an error
    pub fn encrypt(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>, TlsAeadCodecError> {
        let mut frames = Vec::new();
        for chunk in data.chunks(self.max_frame_size as usize) {
            let to_encode = [chunk, &[TLS_APP_DATA]].concat();

            //Associated data is composed of the TLS record
            let associated_data = [
                &[TLS_APP_DATA],
                &TLS_VERSION.to_be_bytes()[..],
                &((chunk.len() + self.cipher.tag_size() + 1) as u16).to_be_bytes(),
            ]
            .concat();

            let encrypted = self.crypto.aead_encrypt(
                self.cipher,
                self.send_key.as_slice(),
                to_encode.as_slice(),
                Self::make_iv(self.send_iv.as_ref(), self.send_seq)?.as_slice(),
                associated_data.as_slice(),
            )?;

            frames.push(encrypted);
            self.send_seq += 1;
        }
        Ok(frames)
    }

    /// Decrypt application data
    /// # Arguments
    /// * `data` - The TLS encoded data frame to decode
    /// # Returns
    /// The decoded application data if successful or an error
    pub fn decrypt_with_header(&mut self, data: &[u8]) -> Result<Vec<u8>, TlsAeadCodecError> {
        let (associated_data, ciphertext) = match data.len() {
            0..MIN_RECORD_SIZE => return Err(TlsAeadCodecError::InvalidData), // Not enough data
            MIN_RECORD_SIZE => return Ok(Vec::new()),                         // Empty frame
            _ => (&data[0..TLS_HDR_SIZE], &data[TLS_HDR_SIZE..]),             // Normal frame
        };
        self.decrypt(ciphertext, associated_data)
    }

    /// Decrypt TLS frame containing application data
    /// # Arguments
    /// * `ciphertext` - The encrypted data to decrypt
    /// * `associated_data` - The associated data to authenticated
    /// # Returns
    /// The decrypted application data if successful or an error
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, TlsAeadCodecError> {
        let msg = self.crypto.aead_decrypt(
            self.cipher,
            self.recv_key.as_slice(),
            ciphertext,
            Self::make_iv(self.recv_iv.as_ref(), self.recv_seq)?.as_slice(),
            associated_data,
        );

        match msg {
            Ok(mut msg) => {
                self.recv_seq += 1;
                msg.drain(msg.len() - 1..); //Remove padding (msg type, 1 byte)
                Ok(msg)
            }
            Err(e) => Err(e.into()),
        }
    }
}
