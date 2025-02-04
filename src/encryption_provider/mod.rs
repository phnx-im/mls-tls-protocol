// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use chrono::{DateTime, Utc};
use futures::{SinkExt, StreamExt};
use openmls::prelude::{
    tls_codec::{self, Deserialize, Serialize},
    TlsDeserialize, TlsSerialize, TlsSize,
};
use openmls_sqlite_storage::Connection;
use openmls_traits::types::{AeadType, HashType};
use std::sync::Arc;
use thiserror::Error;
use tokio::{
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
    sync::Mutex,
};
use tokio_util::codec::{FramedRead, FramedWrite};
use update_policy::UpdatePolicy;

use crate::{
    authentication::{
        leaf_certificate::LeafCertificateSigner, root_certificate::RootCertificate,
        CertificateError,
    },
    handshake::{ClientIdentity, CompletedHandshake, Handshake},
    mls_handshake::{HandshakeError, MlsHandshake, MlsHandshakeError},
    tls_aead::{codec::TlsFrameCodec, SecretUpdate, TlsAeadCodec, TlsAeadCodecError},
};

pub mod update_policy;

#[cfg(test)]
mod tests;

const KEY_SCHEDULE_HASH_FUNCTION: HashType = HashType::Sha2_512;
const AEAD_ALGORITHM: AeadType = AeadType::Aes256Gcm;

#[derive(Error, Debug)]
pub enum EncryptionProviderError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Handshake error: {0}")]
    HandshakeError(#[from] MlsHandshakeError),
    #[error("Decoding error: {0}")]
    CodecError(#[from] tls_codec::Error),
    #[error("Unexpected message: {0}")]
    UnexpectedMessage(String),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] TlsAeadCodecError),
    #[error("Certificate error: {0}")]
    CertificateError(#[from] CertificateError),
    #[error("Received an empty message")]
    EmptyMessage,
    #[error("Sqlite error: {0}")]
    SqliteError(String),
}

pub struct InitialProviderState;

pub struct EstablishedState {
    handshake: MlsHandshake,
    cipher: TlsAeadCodec,
}

pub trait ProtectedTrafficState {
    fn handshake(&self) -> &MlsHandshake;

    fn handshake_mut(&mut self) -> &mut MlsHandshake;

    fn cipher(&mut self) -> &mut TlsAeadCodec;
}

impl ProtectedTrafficState for EstablishedState {
    fn handshake(&self) -> &MlsHandshake {
        &self.handshake
    }

    fn handshake_mut(&mut self) -> &mut MlsHandshake {
        &mut self.handshake
    }

    fn cipher(&mut self) -> &mut TlsAeadCodec {
        &mut self.cipher
    }
}

#[repr(u8)]
#[derive(Debug, TlsSerialize, TlsDeserialize, TlsSize)]
pub enum InnerPlaintext {
    Application(Vec<u8>),
    // An opaque message that is not interpreted by the application layer, but
    // by the underlying handshake.
    Signaling(Vec<u8>),
}

pub struct EncryptionProvider<State, const IS_SERVER: bool> {
    reader: FramedRead<tokio::net::tcp::OwnedReadHalf, TlsFrameCodec>,
    writer: FramedWrite<tokio::net::tcp::OwnedWriteHalf, TlsFrameCodec>,
    state: State,
    address: String,
    update_policy: UpdatePolicy,
}

impl<const IS_SERVER: bool> EncryptionProvider<InitialProviderState, IS_SERVER> {
    pub fn new_from_stream(
        socket: TcpStream,
        update_policy: UpdatePolicy,
    ) -> Result<Self, EncryptionProviderError> {
        let address = socket.peer_addr()?.to_string();
        let (reader, writer) = TcpStream::into_split(socket);
        let state = InitialProviderState;
        let reader = FramedRead::new(reader, TlsFrameCodec);
        let writer = FramedWrite::new(writer, TlsFrameCodec);
        Ok(EncryptionProvider {
            reader,
            writer,
            state,
            address,
            update_policy,
        })
    }
}

impl EncryptionProvider<InitialProviderState, true> {
    pub async fn handshake(
        mut self,
        connection: Arc<Mutex<Connection>>,
        serialized_root_certificate: Vec<u8>,
        serialized_leaf_signer: Vec<u8>,
    ) -> Result<(EncryptionProvider<EstablishedState, true>, ClientIdentity), EncryptionProviderError>
    {
        let leaf_signer = LeafCertificateSigner::deserialize(&serialized_leaf_signer)?;
        let root_certificate = RootCertificate::deserialize(&serialized_root_certificate)?;

        let mut handshake = MlsHandshake::new(connection, leaf_signer, root_certificate);

        let (traffic_secrets, client_identity) = handshake
            .server_handshake(&mut self.reader, &mut self.writer)
            .await?;

        let aead_codec = TlsAeadCodec::new(
            Arc::new(openmls_rust_crypto::RustCrypto::default()),
            true,
            traffic_secrets,
            &[],
            KEY_SCHEDULE_HASH_FUNCTION,
            AEAD_ALGORITHM,
        )?;

        let next_state = self.into_next_state(|_| EstablishedState {
            handshake,
            cipher: aead_codec,
        });

        Ok((next_state, client_identity))
    }
}

impl EncryptionProvider<InitialProviderState, false> {
    pub async fn handshake(
        mut self,
        connection: Arc<Mutex<Connection>>,
        serialized_root_certificate: Vec<u8>,
        serialized_leaf_signer: Vec<u8>,
    ) -> Result<EncryptionProvider<EstablishedState, false>, EncryptionProviderError> {
        let leaf_signer = LeafCertificateSigner::deserialize(&serialized_leaf_signer)?;
        let root_certificate = RootCertificate::deserialize(&serialized_root_certificate)?;

        let mut handshake = MlsHandshake::new(connection, leaf_signer, root_certificate);

        let traffic_secrets = handshake
            .client_handshake(&mut self.reader, &mut self.writer)
            .await?;

        let aead_codec = TlsAeadCodec::new(
            Arc::new(openmls_rust_crypto::RustCrypto::default()),
            false,
            traffic_secrets,
            &[],
            KEY_SCHEDULE_HASH_FUNCTION,
            AEAD_ALGORITHM,
        )?;

        let next_state = self.into_next_state(|_| EstablishedState {
            handshake,
            cipher: aead_codec,
        });

        Ok(next_state)
    }
}

impl<const IS_SERVER: bool> EncryptionProvider<EstablishedState, IS_SERVER> {
    async fn read_bytes_inner(&mut self) -> Result<Option<Vec<u8>>, EncryptionProviderError> {
        let mut message = self.read_message().await?;
        // If the message is a signaling message, we process it and keep
        // listening until we get the next set of bytes.
        loop {
            match message {
                Some(InnerPlaintext::Application(b)) => {
                    return Ok(Some(b));
                }
                Some(InnerPlaintext::Signaling(signaling_message)) => {
                    let (secret_update, response) = self
                        .state
                        .handshake
                        .process_signaling_message(&signaling_message)
                        .await?;
                    if let Some(signaling_message) = response {
                        self.send_message(InnerPlaintext::Signaling(signaling_message))
                            .await?;
                    }
                    if let Some(secret_update) = secret_update {
                        self.update_cipher(secret_update)?;
                    }
                    message = self.read_message().await?;
                }
                None => {
                    return Ok(None);
                }
            }
        }
    }

    fn update_cipher(
        &mut self,
        secret_update: SecretUpdate,
    ) -> Result<(), EncryptionProviderError> {
        self.state
            .cipher
            .update_traffic_secrets(secret_update, IS_SERVER)
            .map_err(EncryptionProviderError::CryptoError)
    }

    pub async fn send_bytes(
        &mut self,
        bytes: Vec<u8>,
        now: DateTime<Utc>,
    ) -> Result<(), EncryptionProviderError> {
        if self.update_policy.update_is_due(now) {
            match self.state.handshake.update_handshake().await {
                Ok((secret_update, message)) => {
                    self.send_message(InnerPlaintext::Signaling(message))
                        .await?;
                    if let Some(secret_update) = secret_update {
                        self.update_cipher(secret_update)?;
                    }
                    self.update_policy.reset(now);
                }
                Err(MlsHandshakeError::HandshakeError(HandshakeError::WaitingForResponse)) => {
                    // If we're waiting for a response, we will try again with
                    // the next set of bytes.
                }
                Err(e) => {
                    return Err(EncryptionProviderError::HandshakeError(e));
                }
            }
        }
        let bytes_len = bytes.len();

        let send_result = self.send_message(InnerPlaintext::Application(bytes)).await;

        self.update_policy
            .increment_bytes_transferred(bytes_len as u64);

        send_result
    }

    pub async fn shutdown(&mut self) -> Result<(), EncryptionProviderError> {
        self.writer.close().await?;
        Ok(())
    }

    pub fn get_address(&self) -> String {
        self.address.clone()
    }
}

impl EncryptionProvider<EstablishedState, false> {
    pub async fn read_bytes(&mut self) -> Result<Vec<u8>, EncryptionProviderError> {
        self.read_bytes_inner()
            .await?
            // Servers should't terminate connections
            .ok_or(EncryptionProviderError::UnexpectedMessage(
                "Expected IpPacket, server terminated connection".to_string(),
            ))
    }
}

impl EncryptionProvider<EstablishedState, true> {
    pub async fn read_bytes(&mut self) -> Result<Option<Vec<u8>>, EncryptionProviderError> {
        self.read_bytes_inner().await
    }
}

impl<State, const IS_SERVER: bool> EncryptionProvider<State, IS_SERVER> {
    fn into_next_state<NextState, F: FnOnce(State) -> NextState>(
        self,
        transform_state: F,
    ) -> EncryptionProvider<NextState, IS_SERVER> {
        EncryptionProvider {
            reader: self.reader,
            writer: self.writer,
            state: transform_state(self.state),
            address: self.address,
            update_policy: self.update_policy,
        }
    }

    pub fn initialize_storage(connection: &mut Connection) -> Result<(), EncryptionProviderError> {
        <MlsHandshake as Handshake<OwnedWriteHalf, OwnedReadHalf>>::initialize_storage(
            &mut *connection,
        )?;
        Ok(())
    }
}

impl<State: ProtectedTrafficState, const IS_SERVER: bool> EncryptionProvider<State, IS_SERVER> {
    async fn send_message(&mut self, msg: InnerPlaintext) -> Result<(), EncryptionProviderError> {
        let msg = msg.tls_serialize_detached()?;
        let msg = self.state.cipher().encrypt(&msg)?;

        for m in msg {
            self.writer.send(&m).await?;
        }
        Ok(())
    }

    async fn read_message(&mut self) -> Result<Option<InnerPlaintext>, EncryptionProviderError> {
        let Some(msg) = self.reader.next().await.transpose()? else {
            return Ok(None);
        };

        let msg_bytes = self.state.cipher().decrypt(&msg.data, &msg.header)?;
        let message = InnerPlaintext::tls_deserialize(&mut msg_bytes.as_slice())?;

        Ok(Some(message))
    }

    pub async fn delete(&mut self) -> Result<(), EncryptionProviderError> {
        self.state.handshake_mut().delete().await?;
        Ok(())
    }

    pub fn epoch(&self) -> u64 {
        self.state.handshake().epoch()
    }
}
