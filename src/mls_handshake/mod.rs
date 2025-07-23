// SPDX-FileCopyrightText: 2024 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use futures::{Sink, SinkExt, Stream, StreamExt};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use state_machine::{
    client::ClientHandshake,
    initialize_storage,
    server::{ServerHandshake, ServerHandshakeState},
};
use std::{borrow::Borrow, sync::Arc};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio_util::bytes::Bytes;
use tracing::instrument;
use uuid::Uuid;

use crate::{
    handshake::{ClientIdentity, CompletedHandshake, Handshake},
    tls_aead::{codec::TlsPacketIn, SecretUpdate, TrafficSecrets},
};

pub use openmls_provider::Provider;
pub(crate) use state_machine::ClientHandshakeState;
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
    #[error("Perform a handshake before sending or receiving messages")]
    Uninitialized,
    #[error(transparent)]
    Persistence(#[from] rusqlite::Error),
    #[error(transparent)]
    SqliteMigration(#[from] refinery::Error),
}

enum MlsHandshakeState {
    None,
    Client(Box<ClientHandshakeState>),
    Server(ServerHandshakeState),
}

pub struct MlsHandshake {
    leaf_signer: SignatureKeyPair,
    connection: Arc<Mutex<Connection>>,
    state: MlsHandshakeState,
}

impl MlsHandshake {
    pub fn new(connection: Arc<Mutex<Connection>>, leaf_signer: SignatureKeyPair) -> Self {
        Self {
            leaf_signer,
            connection,
            state: MlsHandshakeState::None,
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

        let mut connection = self.connection.lock().await;
        let (state, traffic_secrets, client_identity, response_bytes) = ServerHandshake::start(
            &mut connection,
            &self.leaf_signer,
            &first_message_bytes.data,
        )?;
        self.state = MlsHandshakeState::Server(state);

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
        let connection = self.connection.lock().await;

        ClientHandshakeState::create_table(&connection)?;

        // TODO: Check here if we can load a `ClientHandshakeState` from the database
        // and resume the handshake.

        let (handshake_state, client_hello) = ClientHandshake::start(
            &connection,
            &self.leaf_signer,
            server_verifying_key.into(),
            client_id,
        )?;
        tx.send(Bytes::from(client_hello))
            .await
            .map_err(|e| MlsHandshakeError::TransportError(e.into()))?;

        // Wait for the server to return a welcome message
        let Some(Ok(server_hello_bytes)) = rx.next().await else {
            tracing::error!("Invalid handshake ServerHello");
            return Err(MlsHandshakeError::DecodingError);
        };

        let (state, traffic_secrets) =
            handshake_state.receive_server_hello(&connection, &server_hello_bytes.data)?;

        state.store(&connection)?;

        self.state = MlsHandshakeState::Client(Box::new(state));

        Ok(traffic_secrets)
    }
}

impl CompletedHandshake for MlsHandshake {
    type Error = MlsHandshakeError;

    fn epoch(&self) -> u64 {
        match &self.state {
            MlsHandshakeState::None => 0,
            MlsHandshakeState::Client(client_handshake_state) => client_handshake_state.epoch(),
            MlsHandshakeState::Server(server_handshake_state) => server_handshake_state.epoch(),
        }
    }

    async fn update_handshake(&mut self) -> Result<(Option<SecretUpdate>, Vec<u8>), Self::Error> {
        let mut connection = self.connection.lock().await;
        match &mut self.state {
            MlsHandshakeState::None => Err(MlsHandshakeError::Uninitialized),
            MlsHandshakeState::Client(client_handshake_state) => {
                let (client_secret, message_bytes) =
                    client_handshake_state.update(&mut connection, &self.leaf_signer, false)?;
                Ok((
                    Some(SecretUpdate::ClientSecret(client_secret)),
                    message_bytes,
                ))
            }
            MlsHandshakeState::Server(server_handshake_state) => {
                let message_bytes =
                    server_handshake_state.update(&mut connection, &self.leaf_signer, false)?;
                Ok((None, message_bytes))
            }
        }
    }

    async fn process_signaling_message(
        &mut self,
        message_bytes: &[u8],
    ) -> Result<(Option<SecretUpdate>, Option<Vec<u8>>), Self::Error> {
        let mut connection = self.connection.lock().await;
        match &mut self.state {
            MlsHandshakeState::None => Err(MlsHandshakeError::Uninitialized),
            MlsHandshakeState::Client(client_handshake_state) => {
                let (secret_update, message_bytes) = client_handshake_state
                    .receive_signaling_message(&mut connection, &self.leaf_signer, message_bytes)?;
                Ok((secret_update, message_bytes))
            }
            MlsHandshakeState::Server(server_handshake_state) => {
                let (traffic_secrets, message_bytes) = server_handshake_state
                    .receive_signaling_message(&mut connection, &self.leaf_signer, message_bytes)?;
                Ok((Some(SecretUpdate::Both(traffic_secrets)), message_bytes))
            }
        }
    }

    async fn delete(&mut self) -> Result<(), Self::Error> {
        let mut connection = self.connection.lock().await;
        match &self.state {
            MlsHandshakeState::None => (),
            MlsHandshakeState::Client(client_handshake_state) => {
                ClientHandshakeState::delete(&mut connection, client_handshake_state.profile_id)?;
            }
            MlsHandshakeState::Server(server_handshake_state) => {
                server_handshake_state.mls_session.delete(&connection)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{authentication::LEAF_SIGNATURE_SCHEME, tls_aead::codec::TlsFrameCodec};

    use super::*;
    use futures::TryStreamExt;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use tokio_util::codec::{FramedRead, FramedWrite};

    #[tokio::test]
    async fn mls_handshake() {
        let (client_rx, server_tx) = tokio::io::duplex(1024);
        let (server_rx, client_tx) = tokio::io::duplex(1024);

        let mut client_framed_tx = FramedWrite::new(client_tx, TlsFrameCodec)
            .sink_map_err(|e| MlsHandshakeError::TransportError(e.into()));
        let mut server_framed_rx =
            FramedRead::new(server_rx, TlsFrameCodec).map_err(|_| MlsHandshakeError::DecodingError);
        let mut client_framed_rx =
            FramedRead::new(client_rx, TlsFrameCodec).map_err(|_| MlsHandshakeError::DecodingError);
        let mut server_framed_tx = FramedWrite::new(server_tx, TlsFrameCodec)
            .sink_map_err(|e| MlsHandshakeError::TransportError(e.into()));

        let mut client_connection = Connection::open_in_memory().unwrap();
        initialize_storage(&mut client_connection).unwrap();
        let mut server_connection = Connection::open_in_memory().unwrap();
        initialize_storage(&mut server_connection).unwrap();

        let client_signer = SignatureKeyPair::new(LEAF_SIGNATURE_SCHEME).unwrap();
        let server_signer = SignatureKeyPair::new(LEAF_SIGNATURE_SCHEME).unwrap();

        let client_connection = Arc::new(Mutex::new(client_connection));
        let server_connection = Arc::new(Mutex::new(server_connection));
        let mut client_handshake = MlsHandshake::new(client_connection, client_signer);
        let mut server_handshake = MlsHandshake::new(server_connection, server_signer);
        let client_km = Arc::new(Mutex::new(TrafficSecrets::default()));
        let server_km = Arc::new(Mutex::new(TrafficSecrets::default()));

        let server_verifying_key = server_handshake.leaf_signer.public().to_vec();
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
            let (secret_update, message) = client_handshake.update_handshake().await.unwrap();
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
