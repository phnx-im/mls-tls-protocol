// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use chrono::{DateTime, Utc};
use futures::{ready, Sink, SinkExt, Stream, StreamExt};
use hpqmls::authentication::HpqSignatureKeyPair;
use openmls::prelude::{
    tls_codec::{self, Deserialize, Serialize},
    TlsDeserialize, TlsSerialize, TlsSize,
};
use openmls_sqlite_storage::Connection;
use openmls_traits::types::{AeadType, CryptoError, HashType};
use std::{
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
    task::Poll,
};
use thiserror::Error;
use tokio::{
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
    sync::Mutex,
};
use tokio_util::codec::{FramedRead, FramedWrite};
use uuid::Uuid;

use crate::{
    encryption_provider::update_policy::CombinedUpdatePolicy,
    handshake::{ClientIdentity, CompletedHandshake, Handshake},
    mls_handshake::{HandshakeError, MlsHandshake, MlsHandshakeError},
    pre_handshake::{derive_traffic_secrets, PreHandshake},
    tls_aead::{
        codec::TlsFrameCodec,
        stream_sink::{TlsAeadSink, TlsAeadSinkError, TlsAeadStream},
        SecretUpdate, TlsAeadCodec, TrafficSecrets,
    },
};

pub mod builder;
pub mod update_policy;

#[cfg(test)]
mod tests;

pub(crate) const KEY_SCHEDULE_HASH_FUNCTION: HashType = HashType::Sha2_512;
pub(crate) const AEAD_ALGORITHM: AeadType = AeadType::Aes256Gcm;

#[derive(Error, Debug)]
pub enum EncryptionProviderError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("PreHandshake error: {0}")]
    PreHandshakeError(Box<dyn std::error::Error + Send + Sync>),
    #[error("Handshake error: {0}")]
    HandshakeError(#[from] MlsHandshakeError),
    #[error("Codec error: {0}")]
    CodecError(#[from] tls_codec::Error),
    #[error("Unexpected message: {0}")]
    UnexpectedMessage(String),
    #[error(transparent)]
    TlsTransportError(#[from] TlsAeadSinkError),
    #[error("Error deriving traffic secrets from pre-handshake key: {0}")]
    KeyDerivationError(#[from] CryptoError),
}

pub struct UnprotectedHandshakeState {
    reader: FramedRead<OwnedReadHalf, TlsFrameCodec>,
    writer: FramedWrite<OwnedWriteHalf, TlsFrameCodec>,
}

pub struct ProtectedChannels {
    reader: TlsAeadStream<FramedRead<OwnedReadHalf, TlsFrameCodec>>,
    writer: TlsAeadSink<FramedWrite<OwnedWriteHalf, TlsFrameCodec>>,
}

impl ProtectedChannels {
    fn new<const IS_SERVER: bool>(
        reader: FramedRead<OwnedReadHalf, TlsFrameCodec>,
        writer: FramedWrite<OwnedWriteHalf, TlsFrameCodec>,
        traffic_secrets: TrafficSecrets,
    ) -> Result<Self, TlsAeadSinkError> {
        let cipher = TlsAeadCodec::new(
            Arc::new(openmls_rust_crypto::RustCrypto::default()),
            IS_SERVER,
            traffic_secrets,
            &[],
            KEY_SCHEDULE_HASH_FUNCTION,
            AEAD_ALGORITHM,
        )?;

        let cipher = Arc::new(StdMutex::new(cipher));
        let channels = Self {
            reader: TlsAeadStream::new(reader, cipher.clone()),
            writer: TlsAeadSink::new(writer, cipher),
        };
        Ok(channels)
    }

    fn update_cipher<const IS_SERVER: bool>(
        &mut self,
        traffic_secrets: TrafficSecrets,
    ) -> Result<(), TlsAeadSinkError> {
        let secret_update = SecretUpdate::Both(traffic_secrets);
        self.writer
            .update_traffic_secrets(secret_update.clone(), IS_SERVER)?;
        self.reader
            .update_traffic_secrets(secret_update, IS_SERVER)?;
        Ok(())
    }
}

pub struct ProtectedHandshakeState {
    channels: ProtectedChannels,
    session_id: Option<Uuid>,
}

impl ProtectedHandshakeState {
    /// Session ID negotiated during the handshake, if any was negotiated.
    pub fn session_id(&self) -> Option<Uuid> {
        self.session_id
    }
}

#[trait_variant::make(Send)]
pub trait PreHandshakeState {
    /// Perform the handshake with the peer and return the key material.
    async fn client_handshake(
        self,
        handshake: &mut MlsHandshake,
        client_id: Uuid,
        server_verifying_key: &[u8],
    ) -> Result<ProtectedChannels, EncryptionProviderError>;

    async fn server_handshake(
        self,
        handshake: &mut MlsHandshake,
    ) -> Result<(ProtectedChannels, ClientIdentity), EncryptionProviderError>;
}

impl PreHandshakeState for UnprotectedHandshakeState {
    async fn client_handshake(
        self,
        handshake: &mut MlsHandshake,
        client_id: Uuid,
        server_verifying_key: &[u8],
    ) -> Result<ProtectedChannels, EncryptionProviderError> {
        let Self {
            mut reader,
            mut writer,
        } = self;

        let traffic_secrets = handshake
            .client_handshake(&mut reader, &mut writer, client_id, server_verifying_key)
            .await?;

        let channels = ProtectedChannels::new::<false>(reader, writer, traffic_secrets)?;

        Ok(channels)
    }

    async fn server_handshake(
        self,
        handshake: &mut MlsHandshake,
    ) -> Result<(ProtectedChannels, ClientIdentity), EncryptionProviderError> {
        let Self {
            mut reader,
            mut writer,
        } = self;

        let (traffic_secrets, client_identity) =
            handshake.server_handshake(&mut reader, &mut writer).await?;

        let channels = ProtectedChannels::new::<true>(reader, writer, traffic_secrets)?;
        Ok((channels, client_identity))
    }
}

impl PreHandshakeState for ProtectedHandshakeState {
    async fn client_handshake(
        self,
        handshake: &mut MlsHandshake,
        client_id: Uuid,
        server_verifying_key: &[u8],
    ) -> Result<ProtectedChannels, EncryptionProviderError> {
        let mut channels = self.channels;

        let traffic_secrets = handshake
            .client_handshake(
                &mut channels.reader,
                &mut channels.writer,
                client_id,
                server_verifying_key,
            )
            .await?;

        channels.update_cipher::<false>(traffic_secrets)?;

        Ok(channels)
    }

    async fn server_handshake(
        self,
        handshake: &mut MlsHandshake,
    ) -> Result<(ProtectedChannels, ClientIdentity), EncryptionProviderError> {
        let mut channels = self.channels;

        let (traffic_secrets, client_identity) = handshake
            .server_handshake(&mut channels.reader, &mut channels.writer)
            .await?;

        channels.update_cipher::<true>(traffic_secrets)?;

        Ok((channels, client_identity))
    }
}

pub trait ProtectedState {
    fn channels_mut(&mut self) -> &mut ProtectedChannels;
}

impl ProtectedState for ProtectedHandshakeState {
    fn channels_mut(&mut self) -> &mut ProtectedChannels {
        &mut self.channels
    }
}

impl ProtectedState for EstablishedState {
    fn channels_mut(&mut self) -> &mut ProtectedChannels {
        &mut self.channels
    }
}

pub struct EstablishedState {
    handshake: MlsHandshake,
    channels: ProtectedChannels,
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
    state: State,
    address: String,
    update_policy: CombinedUpdatePolicy,
}

impl<State, const IS_SERVER: bool> EncryptionProvider<State, IS_SERVER> {
    pub fn state(&self) -> &State {
        &self.state
    }
}

impl<const IS_SERVER: bool> EncryptionProvider<UnprotectedHandshakeState, IS_SERVER> {
    pub fn new_from_stream(
        socket: TcpStream,
        update_policy: CombinedUpdatePolicy,
    ) -> Result<Self, EncryptionProviderError> {
        let address = socket.peer_addr()?.to_string();
        let (tcp_reader, tcp_writer) = TcpStream::into_split(socket);
        let reader = FramedRead::new(tcp_reader, TlsFrameCodec);
        let writer = FramedWrite::new(tcp_writer, TlsFrameCodec);
        let state = UnprotectedHandshakeState { reader, writer };
        Ok(EncryptionProvider {
            state,
            address,
            update_policy,
        })
    }

    pub async fn new_with_pre_handshake<Ph: PreHandshake>(
        socket: TcpStream,
        update_policy: CombinedUpdatePolicy,
        mut pre_handshake: Ph,
    ) -> Result<EncryptionProvider<ProtectedHandshakeState, IS_SERVER>, EncryptionProviderError>
    {
        let address = socket.peer_addr()?.to_string();
        let (mut reader, mut writer) = TcpStream::into_split(socket);

        let payload = if IS_SERVER {
            pre_handshake
                .server_handshake(&mut reader, &mut writer)
                .await
        } else {
            pre_handshake
                .client_handshake(&mut reader, &mut writer)
                .await
        }
        .map_err(|e| EncryptionProviderError::PreHandshakeError(e.into()))?;

        let traffic_secrets = derive_traffic_secrets(&payload.shared_secret)?;

        let channels = ProtectedChannels::new::<IS_SERVER>(
            FramedRead::new(reader, TlsFrameCodec),
            FramedWrite::new(writer, TlsFrameCodec),
            traffic_secrets,
        )?;

        let state = ProtectedHandshakeState {
            channels,
            session_id: payload.session_id,
        };

        let provider = EncryptionProvider {
            state,
            address,
            update_policy,
        };

        Ok(provider)
    }
}

impl<State: PreHandshakeState> EncryptionProvider<State, true> {
    pub async fn handshake(
        self,
        connection: Arc<Mutex<Connection>>,
        t_leaf_signer: HpqSignatureKeyPair,
        pq_leaf_signer: HpqSignatureKeyPair,
    ) -> Result<(EncryptionProvider<EstablishedState, true>, ClientIdentity), EncryptionProviderError>
    {
        let mut handshake = MlsHandshake::new_server(connection, t_leaf_signer, pq_leaf_signer);

        let (channels, client_identity) = self.state.server_handshake(&mut handshake).await?;

        let next_state = EncryptionProvider {
            state: EstablishedState {
                handshake,
                channels,
            },
            address: self.address,
            update_policy: self.update_policy,
        };

        Ok((next_state, client_identity))
    }
}

impl<State: PreHandshakeState> EncryptionProvider<State, false> {
    pub async fn handshake(
        self,
        connection: Arc<Mutex<Connection>>,
        leaf_signer: HpqSignatureKeyPair,
        client_id: Uuid,
        server_verifying_key: &[u8],
    ) -> Result<EncryptionProvider<EstablishedState, false>, EncryptionProviderError> {
        let mut handshake = MlsHandshake::new_client(connection, leaf_signer);

        let channels = self
            .state
            .client_handshake(&mut handshake, client_id, server_verifying_key)
            .await?;

        let next_state = EncryptionProvider {
            state: EstablishedState {
                handshake,
                channels,
            },
            address: self.address,
            update_policy: self.update_policy,
        };

        Ok(next_state)
    }
}

impl<const IS_SERVER: bool, State: ProtectedState> EncryptionProvider<State, IS_SERVER> {
    fn update_cipher(
        &mut self,
        secret_update: SecretUpdate,
    ) -> Result<(), EncryptionProviderError> {
        self.state
            .channels_mut()
            .writer
            .update_traffic_secrets(secret_update.clone(), IS_SERVER)?;
        self.state
            .channels_mut()
            .reader
            .update_traffic_secrets(secret_update, IS_SERVER)?;
        Ok(())
    }
}

impl<const IS_SERVER: bool> EncryptionProvider<EstablishedState, IS_SERVER> {
    async fn read_bytes_inner(&mut self) -> Result<Option<Vec<u8>>, EncryptionProviderError> {
        let mut message = self.next().await.transpose()?;
        // If the message is a signaling message, we process it and keep
        // listening until we get the next set of bytes.
        loop {
            match message {
                Some(InnerPlaintext::Application(b)) => {
                    tracing::debug!(size_bytes = b.len(), "Received application data");
                    return Ok(Some(b));
                }
                Some(InnerPlaintext::Signaling(signaling_message)) => {
                    tracing::info!(
                        size_bytes = signaling_message.len(),
                        "Received signaling message"
                    );
                    let (secret_update, response) = self
                        .state
                        .handshake
                        .process_signaling_message(&signaling_message)
                        .await?;
                    if let Some(signaling_message) = response {
                        tracing::info!(
                            size_bytes = signaling_message.len(),
                            "Sending signaling response"
                        );
                        self.send(InnerPlaintext::Signaling(signaling_message))
                            .await?;
                    }
                    if let Some(secret_update) = secret_update {
                        self.update_cipher(secret_update)?;
                    }
                    message = self.next().await.transpose()?;
                }
                None => {
                    return Ok(None);
                }
            }
        }
    }

    /// Cancel-safe
    pub async fn read_message(
        &mut self,
    ) -> Result<Option<InnerPlaintext>, EncryptionProviderError> {
        self.next().await.transpose()
    }

    /// Not cancel-safe
    pub async fn process_read_message(
        &mut self,
        message: InnerPlaintext,
    ) -> Result<Option<Vec<u8>>, EncryptionProviderError> {
        match message {
            InnerPlaintext::Application(b) => Ok(Some(b)),
            InnerPlaintext::Signaling(signaling_message) => {
                let (secret_update, response) = self
                    .state
                    .handshake
                    .process_signaling_message(&signaling_message)
                    .await?;
                if let Some(signaling_message) = response {
                    self.send(InnerPlaintext::Signaling(signaling_message))
                        .await?;
                }
                if let Some(secret_update) = secret_update {
                    self.update_cipher(secret_update)?;
                }
                Ok(None)
            }
        }
    }

    pub async fn send_bytes(
        &mut self,
        bytes: Vec<u8>,
        now: DateTime<Utc>,
    ) -> Result<(), EncryptionProviderError> {
        if self.update_policy.update_is_due(now) {
            let pq_update_is_due = self.update_policy.pq_update_is_due(now);
            let update_type = if pq_update_is_due {
                "combined PQ"
            } else {
                "traditional"
            };
            tracing::info!(
                update_type,
                "Update policy triggered key update",
            );
            match self
                .state
                .handshake
                .update_handshake(pq_update_is_due)
                .await
            {
                Ok((secret_update, message)) => {
                    tracing::info!(
                        update_type,
                        signaling_size_bytes = message.len(),
                        "Sending key update signaling message",
                    );
                    self.send(InnerPlaintext::Signaling(message)).await?;
                    if let Some(secret_update) = secret_update {
                        self.update_cipher(secret_update)?;
                    }
                    if pq_update_is_due {
                        self.update_policy.reset_pq(now);
                    } else {
                        self.update_policy.reset_t(now);
                    }
                }
                Err(MlsHandshakeError::HandshakeError(HandshakeError::WaitingForResponse)) => {
                    tracing::debug!("Key update deferred: waiting for response");
                }
                Err(e) => {
                    return Err(EncryptionProviderError::HandshakeError(e));
                }
            }
        }
        let bytes_len = bytes.len();

        tracing::debug!(size_bytes = bytes_len, "Sending application data");

        let send_result = self.send(InnerPlaintext::Application(bytes)).await;

        self.update_policy
            .increment_bytes_transferred(bytes_len as u64);

        send_result
    }

    pub async fn shutdown(&mut self) -> Result<(), EncryptionProviderError> {
        self.state.channels.writer.close().await?;
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
            // Servers shoulnd't terminate connections
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
    pub fn initialize_storage(connection: &mut Connection) -> Result<(), EncryptionProviderError> {
        MlsHandshake::initialize_storage(connection)?;

        Ok(())
    }
}

impl<const IS_SERVER: bool> Stream for EncryptionProvider<EstablishedState, IS_SERVER> {
    type Item = Result<InnerPlaintext, EncryptionProviderError>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let stream = self.get_mut();
        match ready!(Pin::new(&mut stream.state.channels.reader).poll_next(cx)) {
            Some(Ok(packet)) => match InnerPlaintext::tls_deserialize(&mut packet.data.as_ref()) {
                Ok(plaintext) => Poll::Ready(Some(Ok(plaintext))),
                Err(e) => Poll::Ready(Some(Err(e.into()))),
            },
            Some(Err(e)) => Poll::Ready(Some(Err(e.into()))),
            None => Poll::Ready(None),
        }
    }
}

impl<const IS_SERVER: bool> Sink<InnerPlaintext>
    for EncryptionProvider<EstablishedState, IS_SERVER>
{
    type Error = EncryptionProviderError;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().state.channels.writer)
            .poll_ready(cx)
            .map_err(From::from)
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: InnerPlaintext) -> Result<(), Self::Error> {
        let inner_plaintext_bytes = item.tls_serialize_detached()?;
        let sink = self.get_mut();
        Pin::new(&mut sink.state.channels.writer).start_send(inner_plaintext_bytes.into())?;
        Ok(())
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().state.channels.writer)
            .poll_flush(cx)
            .map_err(From::from)
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().state.channels.writer)
            .poll_close(cx)
            .map_err(From::from)
    }
}

impl<const IS_SERVER: bool> EncryptionProvider<EstablishedState, IS_SERVER> {
    pub async fn delete(&mut self) -> Result<(), EncryptionProviderError> {
        self.state.handshake.delete().await?;
        Ok(())
    }

    pub fn t_epoch(&self) -> u64 {
        self.state.handshake.t_epoch()
    }

    pub fn pq_epoch(&self) -> u64 {
        self.state.handshake.pq_epoch()
    }
}
