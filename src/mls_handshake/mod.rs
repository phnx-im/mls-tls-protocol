// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use futures::{Sink, SinkExt, Stream, StreamExt};
use hpqmls::{
    authentication::{HpqSignatureKeyPair, HpqVerifyingKey},
    extension::PqtMode,
};
use openmls::prelude::tls_codec::Deserialize;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use state_machine::{
    client::{ClientHandshake, ClientHandshakeState},
    initialize_storage,
    server::{ServerHandshake, ServerHandshakeState},
};
use std::{borrow::Borrow, mem, sync::Arc};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio_util::bytes::Bytes;
use tracing::{error, instrument};
use uuid::Uuid;

use crate::{
    handshake::{ClientIdentity, CompletedHandshake, Handshake},
    mls_handshake::state_machine::server::ServerHandshakeResult,
    tls_aead::{codec::TlsPacketIn, SecretUpdate, TrafficSecrets},
};

pub use openmls_provider::Provider;
pub use state_machine::HandshakeError;

mod messages;
mod openmls_provider;
mod persistence;
mod state_machine;

#[derive(Debug, Error)]
pub enum MlsHandshakeError {
    #[error("Decoding error")]
    DecodingError,
    #[error("Error using underlying transport: {0}")]
    TransportError(Box<dyn std::error::Error + Send + Sync>),
    #[error(transparent)]
    HandshakeError(#[from] HandshakeError),
    #[error(transparent)]
    Persistence(#[from] rusqlite::Error),
    #[error(transparent)]
    SqliteMigration(#[from] refinery::Error),
    #[error("Invalid state")]
    InvalidState,
}

#[derive(Default)]
enum MlsHandshakeState {
    #[default]
    None,
    InitialClient(HpqSignatureKeyPair),
    InitialServer {
        t_leaf_signer: HpqSignatureKeyPair,
        pq_leaf_signer: HpqSignatureKeyPair,
    },
    Client {
        leaf_signer: HpqSignatureKeyPair,
        state: Box<ClientHandshakeState>,
    },
    Server {
        leaf_signer: HpqSignatureKeyPair,
        state: ServerHandshakeState,
    },
}

pub struct MlsHandshake {
    connection: Arc<Mutex<Connection>>,
    state: MlsHandshakeState,
}

impl MlsHandshake {
    pub fn new_client(
        connection: Arc<Mutex<Connection>>,
        leaf_signer: HpqSignatureKeyPair,
    ) -> Self {
        Self {
            connection,
            state: MlsHandshakeState::InitialClient(leaf_signer),
        }
    }

    pub fn new_server(
        connection: Arc<Mutex<Connection>>,
        t_leaf_signer: HpqSignatureKeyPair,
        pq_leaf_signer: HpqSignatureKeyPair,
    ) -> Self {
        Self {
            connection,
            state: MlsHandshakeState::InitialServer {
                t_leaf_signer,
                pq_leaf_signer,
            },
        }
    }
}

impl Handshake for MlsHandshake {
    type Error = MlsHandshakeError;

    fn initialize_storage(connection: &mut Connection) -> Result<(), Self::Error> {
        initialize_storage(connection)?;
        Ok(())
    }

    async fn server_handshake<
        E: std::error::Error + Send + Sync + 'static,
        S: Sink<Bytes, Error = E> + Unpin,
        R: Stream<Item = Result<TlsPacketIn, E>> + Unpin,
    >(
        &mut self,
        rx: &mut R,
        tx: &mut S,
    ) -> Result<(TrafficSecrets, ClientIdentity), Self::Error> {
        // Read the first message from the client
        let Some(Ok(first_message_bytes)) = rx.next().await else {
            tracing::error!("Failed to read ClientHello");
            return Err(MlsHandshakeError::DecodingError);
        };

        let initial_state = mem::replace(&mut self.state, MlsHandshakeState::None);

        let MlsHandshakeState::InitialServer {
            t_leaf_signer,
            pq_leaf_signer,
        } = initial_state
        else {
            return Err(MlsHandshakeError::InvalidState);
        };

        let mut connection = self.connection.lock().await;
        let ServerHandshakeResult {
            state,
            traffic_secrets,
            client_identity,
            response_bytes,
            mode,
        } = ServerHandshake::start(
            &mut connection,
            &t_leaf_signer,
            &pq_leaf_signer,
            &first_message_bytes.data,
        )?;

        let leaf_signer = match mode {
            PqtMode::ConfOnly => t_leaf_signer,
            PqtMode::ConfAndAuth => pq_leaf_signer,
        };

        self.state = MlsHandshakeState::Server { leaf_signer, state };

        tx.send(Bytes::from(response_bytes))
            .await
            .map_err(|e| MlsHandshakeError::TransportError(e.into()))?;

        Ok((traffic_secrets, client_identity))
    }

    #[instrument(skip_all)]
    async fn client_handshake<
        E: std::error::Error + Send + Sync + 'static,
        S: Sink<Bytes, Error = E> + Unpin,
        R: Stream<Item = Result<TlsPacketIn, E>> + Unpin,
    >(
        &mut self,
        rx: &mut R,
        tx: &mut S,
        client_id: Uuid,
        server_verifying_key: &[u8],
    ) -> Result<TrafficSecrets, MlsHandshakeError> {
        let mut connection = self.connection.lock().await;

        ClientHandshakeState::create_table(&connection)?;
        ClientHandshakeState::delete(&mut connection, client_id)?;

        // TODO: Check here if we can load a `ClientHandshakeState` from the database
        // and resume the handshake.

        let initial_state = mem::replace(&mut self.state, MlsHandshakeState::None);

        let MlsHandshakeState::InitialClient(leaf_signer) = initial_state else {
            return Err(MlsHandshakeError::InvalidState);
        };

        let server_verifying_key = HpqVerifyingKey::tls_deserialize_exact(server_verifying_key)
            .map_err(|e| {
                error!(error = ?e, "Failed to decode server verifying key");
                MlsHandshakeError::DecodingError
            })?;
        let (handshake_state, client_hello) =
            ClientHandshake::start(&connection, &leaf_signer, server_verifying_key, client_id)?;
        tx.send(Bytes::from(client_hello))
            .await
            .map_err(|e| MlsHandshakeError::TransportError(e.into()))?;

        // Wait for the server to return a welcome message
        let server_hello_bytes = match rx.next().await {
            Some(Ok(server_hello_bytes)) => server_hello_bytes,
            Some(Err(e)) => {
                tracing::error!(error = ?e, "Invalid handshake ServerHello");
                return Err(MlsHandshakeError::DecodingError);
            }
            None => {
                tracing::error!("No ServerHello received");
                return Err(MlsHandshakeError::DecodingError);
            }
        };

        let (state, traffic_secrets) =
            handshake_state.receive_server_hello(&connection, &server_hello_bytes.data)?;

        state.store(&connection)?;

        self.state = MlsHandshakeState::Client {
            leaf_signer,
            state: Box::new(state),
        };

        Ok(traffic_secrets)
    }
}

impl CompletedHandshake for MlsHandshake {
    type Error = MlsHandshakeError;

    fn t_epoch(&self) -> u64 {
        match &self.state {
            MlsHandshakeState::Client { state, .. } => state.t_epoch(),
            MlsHandshakeState::Server { state, .. } => state.t_epoch(),
            _ => 0,
        }
    }

    fn pq_epoch(&self) -> u64 {
        match &self.state {
            MlsHandshakeState::Client { state, .. } => state.pq_epoch(),
            MlsHandshakeState::Server { state, .. } => state.pq_epoch(),
            _ => 0,
        }
    }

    async fn update_handshake(
        &mut self,
        pq: bool,
    ) -> Result<(Option<SecretUpdate>, Vec<u8>), Self::Error> {
        let mut connection = self.connection.lock().await;
        match &mut self.state {
            MlsHandshakeState::Client { leaf_signer, state } => {
                let (client_secret, message_bytes) =
                    state.update(&mut connection, &leaf_signer, false, pq)?;
                Ok((
                    Some(SecretUpdate::ClientSecret(client_secret)),
                    message_bytes,
                ))
            }
            MlsHandshakeState::Server { leaf_signer, state } => {
                let message_bytes = state.update(&mut connection, &leaf_signer, false, pq)?;
                Ok((None, message_bytes))
            }
            _ => Err(MlsHandshakeError::InvalidState),
        }
    }

    async fn process_signaling_message(
        &mut self,
        message_bytes: &[u8],
    ) -> Result<(Option<SecretUpdate>, Option<Vec<u8>>), Self::Error> {
        let mut connection = self.connection.lock().await;
        match &mut self.state {
            MlsHandshakeState::Client { leaf_signer, state } => {
                let (secret_update, message_bytes) =
                    state.receive_signaling_message(&mut connection, leaf_signer, message_bytes)?;
                Ok((secret_update, message_bytes))
            }
            MlsHandshakeState::Server { leaf_signer, state } => {
                let (traffic_secrets, message_bytes) = state.receive_signaling_message(
                    &mut connection,
                    &leaf_signer,
                    message_bytes,
                )?;
                Ok((Some(SecretUpdate::Both(traffic_secrets)), message_bytes))
            }
            _ => Err(MlsHandshakeError::InvalidState),
        }
    }

    async fn delete(&mut self) -> Result<(), Self::Error> {
        let mut connection = self.connection.lock().await;
        match &self.state {
            MlsHandshakeState::Client { state, .. } => {
                ClientHandshakeState::delete(&mut connection, state.profile_id)?;
            }
            MlsHandshakeState::Server { state, .. } => {
                state.mls_session.delete(&connection)?;
            }
            _ => (),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        mls_handshake::state_machine::{PQ_AUTH_CIPHERSUITE, T_AUTH_CIPHERSUITE},
        tls_aead::codec::TlsFrameCodec,
    };

    use super::*;
    use futures::TryStreamExt;
    use hpqmls::authentication::HpqSigner;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use tokio_util::codec::{FramedRead, FramedWrite};

    #[tokio::test]
    async fn mls_handshake() {
        let server_t_signer = HpqSignatureKeyPair::new(T_AUTH_CIPHERSUITE.into()).unwrap();
        let server_pq_signer = HpqSignatureKeyPair::new(PQ_AUTH_CIPHERSUITE.into()).unwrap();

        for mode in [PqtMode::ConfOnly, PqtMode::ConfAndAuth] {
            let (client_rx, server_tx) = tokio::io::duplex(1024);
            let (server_rx, client_tx) = tokio::io::duplex(1024);

            let mut client_framed_tx = FramedWrite::new(client_tx, TlsFrameCodec)
                .sink_map_err(|e| MlsHandshakeError::TransportError(e.into()));
            let mut server_framed_rx = FramedRead::new(server_rx, TlsFrameCodec)
                .map_err(|_| MlsHandshakeError::DecodingError);
            let mut client_framed_rx = FramedRead::new(client_rx, TlsFrameCodec)
                .map_err(|_| MlsHandshakeError::DecodingError);
            let mut server_framed_tx = FramedWrite::new(server_tx, TlsFrameCodec)
                .sink_map_err(|e| MlsHandshakeError::TransportError(e.into()));

            let mut client_connection = Connection::open_in_memory().unwrap();
            initialize_storage(&mut client_connection).unwrap();
            let mut server_connection = Connection::open_in_memory().unwrap();
            initialize_storage(&mut server_connection).unwrap();

            let signature_scheme = match mode {
                PqtMode::ConfOnly => T_AUTH_CIPHERSUITE.into(),
                PqtMode::ConfAndAuth => PQ_AUTH_CIPHERSUITE.into(),
            };
            let client_signer = HpqSignatureKeyPair::new(signature_scheme).unwrap();

            let server_verifying_key = match mode {
                PqtMode::ConfOnly => server_t_signer.verifying_key().to_bytes(),
                PqtMode::ConfAndAuth => server_pq_signer.verifying_key().to_bytes(),
            };

            let client_connection = Arc::new(Mutex::new(client_connection));
            let server_connection = Arc::new(Mutex::new(server_connection));
            let mut client_handshake = MlsHandshake::new_client(client_connection, client_signer);
            let mut server_handshake = MlsHandshake::new_server(
                server_connection,
                server_t_signer.clone(),
                server_pq_signer.clone(),
            );
            let client_km = Arc::new(Mutex::new(TrafficSecrets::default()));
            let server_km = Arc::new(Mutex::new(TrafficSecrets::default()));

            let ckm = client_km.clone();
            let client_id = Uuid::new_v4();
            let client_task = tokio::spawn(async move {
                let mut tf = ckm.lock().await;
                *tf = client_handshake
                    .client_handshake(
                        &mut client_framed_rx,
                        &mut client_framed_tx,
                        client_id,
                        &server_verifying_key,
                    )
                    .await
                    .unwrap();
                let (secret_update, message) =
                    client_handshake.update_handshake(false).await.unwrap();
                if let Some(secret_update) = secret_update {
                    tf.update(secret_update);
                }
                client_framed_tx.send(Bytes::from(message)).await.unwrap();
                let response = client_framed_rx.next().await.unwrap().unwrap();
                let (secret_update, message) = client_handshake
                    .process_signaling_message(&response.data)
                    .await
                    .unwrap();
                if let Some(secret_update) = secret_update {
                    tf.update(secret_update);
                }
                assert!(message.is_none());
            });

            let skm = server_km.clone();
            let server_task = tokio::spawn(async move {
                let mut tf = skm.lock().await;
                let client_identity;
                (*tf, client_identity) = server_handshake
                    .server_handshake(&mut server_framed_rx, &mut server_framed_tx)
                    .await
                    .unwrap();
                assert_eq!(client_identity.0, client_id.as_bytes());
                let message_bytes = server_framed_rx.next().await.unwrap().unwrap();
                let (secret_update, message) = server_handshake
                    .process_signaling_message(&message_bytes.data)
                    .await
                    .unwrap();
                if let Some(secret_update) = secret_update {
                    tf.update(secret_update);
                }
                server_framed_tx
                    .send(Bytes::from(message.unwrap()))
                    .await
                    .unwrap();
            });

            tokio::try_join!(client_task, server_task).unwrap();
            assert_eq!(
                client_km.lock().await.client_secret,
                server_km.lock().await.client_secret
            );
            assert_eq!(
                client_km.lock().await.server_secret,
                server_km.lock().await.server_secret
            );
        }
    }
}
